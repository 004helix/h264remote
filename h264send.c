#define _GNU_SOURCE

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <err.h>

/* libevent */
#include <event2/event_struct.h>
#include <event2/event.h>

/* openssl */
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define STDIN_READ_SIZE 131072
#define CONNECT_TIMEOUT 30
#define RETRY_INTERVAL 1
#define READ_TIMEOUT 30


static struct event_base *eb;
static enum { UNKNOWN, H264, HEVC } format = UNKNOWN;

static unsigned char magic[16] = "0123456789abcdef";
static char stdin_buffer[4194304]; // 4MiB
static char *buffer = stdin_buffer;
static size_t bufsize = sizeof(stdin_buffer);
static size_t buflen = 0;

static uint8_t boundary;
static uint8_t key[32];
uint8_t iv[16];
int ivlen = 0;


struct outbuffer {
    uint32_t size;
    uint32_t tv_sec;
    uint32_t tv_nsec;
    unsigned char buffer[sizeof(stdin_buffer)];
} __attribute__((__packed__));
static unsigned char zerohdr[12] = "\0\0\0\0\0\0\0\0\0\0\0\0";
static unsigned char delimiter[4] = "\0\0\0\1";
static struct outbuffer out;
static size_t outlen = 0;

static int sock;
static int sndbuf = 0;
static int connected = 0;
static struct event ev;
static socklen_t ss_size;
static struct sockaddr_storage ss;
static EVP_CIPHER_CTX *ctx;


static void make_connect(int fd, short event, void *arg);
static void on_connect(int fd, short event, void *arg);
static void on_stdin_read(int fd, short event, void *arg);


void nalu(const unsigned char *unit, size_t len)
{
    struct timeval tv;
    uint8_t nal_type;

    /* empty unit */
    if (len < 2)
        return;

    if (*unit & 0x80) {
        warnx("forbidden_zero_bit != 0");
        return;
    }

    /* parse unit type */
    switch (format) {
        case H264:
            nal_type = *unit & 0x1f;
            break;
        case HEVC:
            nal_type = (*unit >> 1) & 0x3f;
            break;
        case UNKNOWN: {
            /* try hevc */
            nal_type = (*unit >> 1) & 0x3f;
            /* VPS || SPS || PPS */
            if (nal_type == 32 || nal_type == 33 || nal_type == 34) {
                boundary = nal_type;
                format = HEVC;
            } else {
                /* try h264 */
                nal_type = *unit & 0x1f;
                /* SPS || PPS */
                if (nal_type == 7 || nal_type == 8) {
                    boundary = nal_type;
                    format = H264;
                }
            }
            if (format == UNKNOWN) {
                warnx("can't detect h264/hevc format (bad stream?)");
                return;
            }
        }
    }

    //warnx("nal_type=%u, len=%lu", nal_type, len);

    switch (connected) {
        case 0: // not connected
        case 1: // connected, waiting for iv
            break;

        case 2: // connected, encryption context initialized, waiting for boundary
            if (nal_type == boundary)
                connected++;
            else
                break;

        default: {
            struct timespec ts;
            int enclen;

            /* prepend VPS, SPS and PPS to I-frame */
            if ((format == HEVC && (nal_type == 32 || nal_type == 33 || nal_type == 34)) ||
                (format == H264 && (nal_type == 7 || nal_type == 8))) {

                /* check buffer length */
                if (outlen + len + 4 >= sizeof(out.buffer)) {
                    warnx("send(2): encryption buffer overflow");
                    goto reconnect;
                }

                /* append delimiter if it's not first encrypted unit */
                if (outlen > 0) {
                    if (1 != EVP_EncryptUpdate(ctx, out.buffer + outlen, &enclen, delimiter, 4)) {
                        ERR_print_errors_fp(stderr);
                        warnx("connection closed due to ssl errors");
                        goto reconnect;
                    }

                    outlen += enclen;
                }

                /* append unit */
                if (1 != EVP_EncryptUpdate(ctx, out.buffer + outlen, &enclen, unit, len)) {
                    ERR_print_errors_fp(stderr);
                    warnx("connection closed due to ssl errors");
                    goto reconnect;
                }

                outlen += enclen;
                return;
            }

            /* check buffer length */
            if (outlen + len + 4 >= sizeof(out.buffer)) {
                warnx("send(2): encryption buffer overflow");
                goto reconnect;
            }

            /* append delimiter if it's not first encrypted unit */
            if (outlen > 0) {
                if (1 != EVP_EncryptUpdate(ctx, out.buffer + outlen, &enclen, delimiter, 4)) {
                    ERR_print_errors_fp(stderr);
                    warnx("connection closed due to ssl errors");
                    goto reconnect;
                }

                outlen += enclen;
            }

            /* append unit */
            if (1 != EVP_EncryptUpdate(ctx, out.buffer + outlen, &enclen, unit, len)) {
                ERR_print_errors_fp(stderr);
                warnx("connection closed due to ssl errors");
                goto reconnect;
            }

            outlen += enclen;

            /* build header (already encrypted) */
            clock_gettime(CLOCK_MONOTONIC, &ts);
            out.size ^= htonl(outlen);
            out.tv_sec ^= htonl(ts.tv_sec);
            out.tv_nsec ^= htonl(ts.tv_nsec);

            /* send frame */
            if (send(sock, &out, outlen + 12, MSG_NOSIGNAL) < outlen + 12) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                    warnx("send(2): send buffer overflow");
                } else
                    warn("send(2)");
                goto reconnect;
            }

            /* encrypt new zero header */
            if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)&out, &enclen, zerohdr, sizeof(zerohdr))) {
                ERR_print_errors_fp(stderr);
                warnx("connection closed due to ssl errors");
                goto reconnect;
            }

            outlen = 0;
        }
    }

    return;

    reconnect:
    event_del(&ev);
    close(sock);
    connected = 0;
    EVP_CIPHER_CTX_free(ctx);
    event_assign(&ev, eb, -1, 0, make_connect, NULL);
    tv.tv_sec = RETRY_INTERVAL;
    tv.tv_usec = 0;
    event_add(&ev, &tv);
}


static void on_read(int fd, short event, void *arg)
{
    unsigned char emagic[sizeof(magic)];
    struct timeval tv;
    ssize_t len;
    int enclen;

    if (event & EV_TIMEOUT) {
        warnx("recv(2) timeout");
        goto reconnect;
    }

    if (connected > 1) {
        len = recv(sock, iv, 1, 0);

        if (len == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return;

            warn("recv(2)");
        }

        if (len == 0)
            warnx("connection prematurely closed");
        else
            warnx("garbage in connection");

        EVP_CIPHER_CTX_free(ctx);
        goto reconnect;
    }

    len = recv(sock, iv + ivlen, sizeof(iv) - ivlen, 0);

    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        warn("recv(2)");
        goto reconnect;
    }

    if (len == 0) {
        warnx("connection prematurely closed");
        goto reconnect;
    }

    ivlen += len;

    if (ivlen < sizeof(iv)) {
        event_assign(&ev, eb, sock, EV_READ | EV_TIMEOUT, on_read, NULL);
        tv.tv_sec = READ_TIMEOUT;
        tv.tv_usec = 0;
        event_add(&ev, &tv);
        return;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        warnx("connection closed due to ssl errors");
        goto reconnect;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        warnx("connection closed due to ssl errors");
        goto reconnect;
    }

    if (1 != EVP_EncryptUpdate(ctx, emagic, &enclen, magic, sizeof(magic))) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        warnx("connection closed due to ssl errors");
        goto reconnect;
    }

    if (enclen != sizeof(magic)) {
        EVP_CIPHER_CTX_free(ctx);
        warnx("connection closed due to ssl failure");
        goto reconnect;
    }

    if (send(sock, emagic, enclen, MSG_NOSIGNAL) != enclen) {
        warn("send(2)");
        EVP_CIPHER_CTX_free(ctx);
        goto reconnect;
    }

    /* encrypt zero header */
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char *)&out, &enclen, zerohdr, sizeof(zerohdr))) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        warnx("connection closed due to ssl errors");
        goto reconnect;
    }

    outlen = 0;

    event_assign(&ev, eb, sock, EV_READ, on_read, NULL);
    event_add(&ev, NULL);
    connected++;
    return;

    reconnect:
    close(sock);
    connected = 0;
    event_assign(&ev, eb, -1, 0, make_connect, NULL);
    tv.tv_sec = RETRY_INTERVAL;
    tv.tv_usec = 0;
    event_add(&ev, &tv);
}


static void on_connect(int fd, short event, void *arg)
{
    struct timeval tv;
    socklen_t len;
    int error;

    if (event & EV_TIMEOUT) {
        warnx("connect(2) timeout");
        goto retry;
    }

    len = sizeof(error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
        warn("getsockopt(2)");
        goto retry;
    }

    if (error != 0) {
        errno = error;
        warn("connect(2)");
        goto retry;
    }

    if (sndbuf > 0 && setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) {
        warn("setsockopt(2) SO_SNDBUF");
        goto retry;
    }

    warnx("connect: success");
    connected++;

    event_assign(&ev, eb, sock, EV_READ | EV_TIMEOUT, on_read, NULL);
    tv.tv_sec = READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(&ev, &tv);
    return;

    retry:
    if (sock != -1)
        close(sock);
    event_assign(&ev, eb, -1, 0, make_connect, NULL);
    tv.tv_sec = RETRY_INTERVAL;
    tv.tv_usec = 0;
    event_add(&ev, &tv);
    return;
}


static void make_connect(int fd, short event, void *arg)
{
    struct timeval tv;
    char buffer[64];
    int ret;

    if (ss.ss_family == AF_INET6)
        warnx("connect: [%s]:%d",
              inet_ntop(AF_INET6, &(*((struct sockaddr_in6 *)&ss)).sin6_addr, buffer, sizeof(buffer)),
              ntohs((*((struct sockaddr_in6 *)&ss)).sin6_port));
    else if (ss.ss_family == AF_INET)
        warnx("connect: %s:%d",
              inet_ntop(AF_INET, &(*((struct sockaddr_in *)&ss)).sin_addr, buffer, sizeof(buffer)),
              ntohs((*((struct sockaddr_in *)&ss)).sin_port));
    else
        warnx("connect");

    ivlen = 0;
    outlen = 0;
    connected = 0;
    sock = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

    if (sock == -1) {
        warn("unable to create socket");
        goto retry;
    }

    ret = connect(sock, (struct sockaddr *)&ss, ss_size);

    if (ret == 0) {
        on_connect(sock, EV_WRITE, NULL);
        return;
    } else if (errno == EINPROGRESS) {
        event_assign(&ev, eb, sock, EV_WRITE | EV_TIMEOUT, on_connect, NULL);
        tv.tv_sec = CONNECT_TIMEOUT;
        tv.tv_usec = 0;
        event_add(&ev, &tv);
    } else {
        warn("unable to connect");
        goto retry;
    }

    return;

    /* reconnect in 1 second */
    retry:
    if (sock != -1)
        close(sock);
    event_assign(&ev, eb, -1, 0, make_connect, NULL);
    tv.tv_sec = RETRY_INTERVAL;
    tv.tv_usec = 0;
    event_add(&ev, &tv);
    return;
}


static void on_stdin_read(int fd, short event, void *arg)
{
    size_t size;
    ssize_t ret;
    char *unit;

    size = bufsize - buflen;
    if (size > STDIN_READ_SIZE)
        size = STDIN_READ_SIZE;

    if (size == 0) {
        warnx("stdin buffer overflow (bad stream?)");
        exit(EXIT_FAILURE);
    }

    ret = read(STDIN_FILENO, buffer + buflen, size);

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        err(EXIT_FAILURE, "failed to read from stdin");
    }

    if (ret == 0) {
        nalu((unsigned char *)buffer + 4, buflen - 4);
        exit(EXIT_SUCCESS);
    }

    buflen += ret;

    if (buflen < 8)
        return;

    for (unit = buffer; unit < buffer + buflen - 4;) {
        char *next = (char *)memmem(unit + 4, buflen - (unit - buffer) - 4, delimiter, 4);

        if (!next)
            break;

        nalu((unsigned char *)unit + 4, next - unit - 4);

        unit = next;
    }

    if (unit > buffer) {
        bufsize -= unit - buffer;
        buflen -= unit - buffer;
        buffer = unit;

        if (bufsize < sizeof(stdin_buffer) / 2) {
            memcpy(stdin_buffer, buffer, buflen);
            bufsize = sizeof(stdin_buffer);
            buffer = stdin_buffer;
        }
    }

    return;
}


static void usage(int exit_code)
{
    fprintf(stderr, "Usage: <generator> | h264send [option]...\n"
            "\n"
            "Options:\n"
            " -h, --help            show this help\n"
            " -a, --addr=ADDRESS    feed address (required)\n"
            " -p, --port=PORT       feed port (required)\n"
            " -k, --key=KEY         chacha20 key, 256 bit,\n"
            "                       base64 encoded (required)\n"
            " -s, --sndbuf=SIZE     tcp send buffer size; if send buffer\n"
            "                       overflow, connection will be dropped\n"
            "\n");
    exit(exit_code);
}


int main(int argc, char **argv)
{
    struct event stdin_ev;
    char *b64key = NULL;
    char *addr = NULL;
    int port = 0;
    int c;

    /* init libevent */
    eb = event_base_new();
    if (eb == NULL)
        err(EXIT_FAILURE, "event_base_new");

    /* init signals */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    /* parse arguments */
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help", no_argument, NULL, 'h'},
            {"addr", required_argument, NULL, 'a'},
            {"port", required_argument, NULL, 'p'},
            {"sndbuf", required_argument, NULL, 's'},
            {"key", required_argument, NULL, 'k'},
            {NULL, 0, NULL, 0}
        };

        c = getopt_long(argc, argv, "ha:p:s:k:", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(0);

            case 'a':
                addr = strdup(optarg);
                break;

            case 'p': {
                char *endptr;
                port = strtol(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    warnx("bad port: %s\n", endptr);
                    usage(EXIT_FAILURE);
                }
                if (port < 1 || port > 65535) {
                    warnx("port out of range: %d", port);
                    usage(EXIT_FAILURE);
                }
                break;
            }

            case 's': {
                char *endptr;
                sndbuf = strtol(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    warnx("bad sndbuf: %s", endptr);
                    usage(EXIT_FAILURE);
                }
                break;
            }

            case 'k':
                b64key = strdup(optarg);
                break;

            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                abort();
        }
    }

    if (optind < argc) {
        warnx("unknown argument: %s", argv[optind]);
        usage(EXIT_FAILURE);
    }

    if (isatty(STDIN_FILENO))
        usage(EXIT_FAILURE);

    if (addr == NULL || port == 0) {
        warnx("you should specify address and port to connect to");
        usage(EXIT_FAILURE);
    }

    if (b64key == NULL) {
        warnx("you should specify encryption key");
        usage(EXIT_FAILURE);
    }

    /* parse encryption key */
    if (strlen(b64key) == 44 && b64key[43] == '=') {
        BIO *b64, *bmem;

        b64 = BIO_new(BIO_f_base64());
        bmem = BIO_new_mem_buf(b64key, 44);
        bmem = BIO_push(b64, bmem);

        BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

        if (BIO_read(bmem, key, 32) != 32) {
            warnx("unable to decode encryption key: it should be base64 encoded");
            usage(EXIT_FAILURE);
        }

        BIO_free_all(bmem);
    } else {
        warnx("wrong encryption key: it should be 256 bit, base64 encoded");
        usage(EXIT_FAILURE);
    }

    /* create sockaddr_storage from addr and port */
    if (inet_pton(AF_INET6, addr, &(*((struct sockaddr_in6 *)&ss)).sin6_addr) != 0) {
        ss.ss_family = AF_INET6;
        (*((struct sockaddr_in6 *)&ss)).sin6_port = htons(port);
        ss_size = sizeof(struct sockaddr_in6);
    } else if (inet_pton(AF_INET, addr, &(*((struct sockaddr_in *)&ss)).sin_addr) != 0) {
        ss.ss_family = AF_INET;
        (*((struct sockaddr_in *)&ss)).sin_port = htons(port);
        ss_size = sizeof(struct sockaddr_in);
    } else {
        warnx("Can't parse address: %s", addr);
        usage(EXIT_FAILURE);
    }

    /* make stdin non-blocking */
    c = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (c != -1)
        if (fcntl(STDIN_FILENO, F_SETFL, c | O_NONBLOCK) < 0)
            warn("failed to make stdin non-blocking");

    /* start stdin read loop */
    event_assign(&stdin_ev, eb, STDIN_FILENO, EV_READ | EV_PERSIST, on_stdin_read, NULL);
    event_add(&stdin_ev, NULL);

    /* make connect */
    make_connect(0, 0, NULL);

    /* event_base start */
    event_base_dispatch(eb);

    return 0;
}
