#define _GNU_SOURCE

#include <arpa/inet.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <alloca.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <err.h>

/* libevent */
#include <event2/event_struct.h>
#include <event2/event.h>

/* openssl */
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* pthread */
#include <pthread.h>

#define READ_TIMEOUT 30
#define MAX_QUEUE_SIZE 1024

struct frame_header {
    uint32_t size;
    uint32_t tv_sec;
    uint32_t tv_nsec;
} __attribute__((__packed__));

struct frame {
    struct frame *next;
    struct timespec ts;
    unsigned long size;
    unsigned char data[0];
};

struct client {
    char addr[64];
    struct event ev;
    EVP_CIPHER_CTX *ctx;
    struct frame *frame;
    unsigned char magic[16];
    int magiclen;
};

static char magic[16] = "0123456789abcdef";
static unsigned char delimiter[4] = "\0\0\0\1";
static unsigned long inlen = 0;
static unsigned char inbuffer[2097152];  // 2MiB
static struct client *curr = NULL;
static struct event_base *eb;
uint8_t key[32];

/* frame fifo */
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static struct frame *head = NULL;
static struct frame *tail = NULL;
static int qsize = 0;

/* current latency */
static int64_t latency = 0;


static void usage(int exit_code)
{
    fprintf(stderr, "Usage: <sender> | h264feed [option]...\n"
            "\n"
            "Options:\n"
            " -h, --help            show this help\n"
            " -a, --addr=ADDRESS    feed address (required)\n"
            " -p, --port=PORT       feed port (required)\n"
            " -k, --key=KEY         chacha20 key, 256 bit,\n"
            "                       base64 encoded (required)\n"
            "\n");
    exit(exit_code);
}


void process_frame(struct frame *frame)
{
    struct iovec iov[2];
    struct timespec ts;
    int64_t frame_nsec;
    int64_t local_nsec;
    int64_t wait_nsec;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    local_nsec = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    frame_nsec = (int64_t)frame->ts.tv_sec * 1000000000LL + frame->ts.tv_nsec;

    wait_nsec = frame_nsec - local_nsec + latency;

    /* 5 sec */
    if (wait_nsec > 5000000000LL || wait_nsec < -5000000000LL) {
        latency = local_nsec - frame_nsec;
        wait_nsec = 0;
    }

    if (wait_nsec < 0) {
        latency -= wait_nsec;
        wait_nsec = 0;
    }

    if (wait_nsec > 0) {
        ts.tv_sec += wait_nsec / 1000000000LL;
        ts.tv_nsec += wait_nsec % 1000000000LL;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }

        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL);

        /* compensate time drift: 0.1ms */
        latency -= 100000LL;
    }

    /*
    if (latency < 0)
        warnx("%p %d -%lld.%09lld %lu", frame, qsize, -latency / 1000000000LL, -latency % 1000000000LL, frame->size);
    else
        warnx("%p %d %lld.%09lld %lu", frame, qsize, latency / 1000000000LL, latency % 1000000000LL, frame->size);
    */

    iov[0].iov_base = frame->data;
    iov[0].iov_len = frame->size;
    iov[1].iov_base = delimiter;
    iov[1].iov_len = sizeof(delimiter);

    if (writev(STDOUT_FILENO, iov, 2) < frame->size + sizeof(delimiter))
        err(EXIT_FAILURE, "writev(2)");

    free(frame);
}


void *worker(void *unused __attribute__((unused)))
{
    write(STDOUT_FILENO, delimiter, sizeof(delimiter));

    pthread_mutex_lock(&lock);

    for (;;) {
        /* process frames queue */
        while (head) {
            struct frame *frame = head;
            head = head->next;

            if (head == NULL)
                tail = NULL;

            qsize--;

            pthread_mutex_unlock(&lock);
            process_frame(frame);
            pthread_mutex_lock(&lock);
        }

        /* queue is empty */
        if (pthread_cond_wait(&cond, &lock))
            errx(EXIT_FAILURE, "pthread_cond_wait() error");
    }
}


static void add_frame(struct frame *frame)
{
    frame->next = NULL;

    pthread_mutex_lock(&lock);

    if (qsize == MAX_QUEUE_SIZE) {
        pthread_mutex_unlock(&lock);
        return;
    }

    if (tail == NULL) {
        head = tail = frame;
        goto out;
    }

    tail->next = frame;
    tail = frame;

    out:
    qsize++;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);
}


static void on_read(int fd, short ev, void *arg)
{
    struct client *c = (struct client *)arg;
    unsigned long remain;
    ssize_t len;
    int outlen;

    if (ev & EV_TIMEOUT) {
        warnx("client %s recv(2): timeout", c->addr);
        goto close;
    }

    if (curr != c) {
        warnx("client %s closed: old connection", c->addr);
        goto close;
    }

    len = recv(fd, inbuffer + inlen, sizeof(inbuffer) - inlen, 0);

    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        warn("client %s recv(2)", c->addr);
        goto close;
    }

    if (len == 0) {
        warnx("client %s closed connection", c->addr);
        goto close;
    }

    inlen += len;

    parse:
    if (inlen < sizeof(struct frame_header))
        return;

    if (c->frame == NULL) {
        struct frame_header hdr;
        unsigned long size;

        if (1 != EVP_DecryptUpdate(c->ctx, (unsigned char *)&hdr, &outlen,
                                   inbuffer, sizeof(struct frame_header))) {
            ERR_print_errors_fp(stderr);
            warnx("client %s closed due to ssl errors", c->addr);
            goto close;
        }

        size = ntohl(hdr.size);

        if (sizeof(struct frame_header) + size > sizeof(inbuffer)) {
            warnx("client %s parse(): frame too long", c->addr);
            goto close;
        }

        c->frame = malloc(sizeof(struct frame) + size);
        if (c->frame == NULL) {
            warnx("client %s malloc(3): not enough memory", c->addr);
            goto close;
        }

        c->frame->size = size;
        c->frame->ts.tv_sec = ntohl(hdr.tv_sec);
        c->frame->ts.tv_nsec = ntohl(hdr.tv_nsec);
    }

    if (inlen < sizeof(struct frame_header) + c->frame->size)
        return;

    if (1 != EVP_DecryptUpdate(c->ctx, c->frame->data, &outlen,
                               inbuffer + sizeof(struct frame_header), c->frame->size)) {
        ERR_print_errors_fp(stderr);
        warnx("client %s closed due to ssl errors", c->addr);
        goto close;
    }

    if (outlen != c->frame->size) {
        warnx("client %s closed due to ssl failure", c->addr);
        goto close;
    }

    add_frame(c->frame);

    c->frame = NULL;

    remain = inlen - sizeof(struct frame_header) - outlen;
    if (remain > 0) {
        memmove(inbuffer, inbuffer + sizeof(struct frame_header) + outlen, remain);
        inlen = remain;
        goto parse;
    }

    inlen = 0;
    return;

    close:
    if (c->frame)
        free(c->frame);
    EVP_CIPHER_CTX_free(c->ctx);
    event_del(&c->ev);
    close(fd);
    free(c);
}


static void on_read_verify(int fd, short ev, void *arg)
{
    struct client *c = (struct client *)arg;
    struct timeval tv;
    unsigned char *m;
    ssize_t len;
    int mlen;

    if (ev & EV_TIMEOUT) {
        warnx("client %s recv(2): timeout", c->addr);
        goto close;
    }

    len = recv(fd, c->magic + c->magiclen, sizeof(c->magic) - c->magiclen, 0);

    if (len == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        warn("client %s recv(2)", c->addr);
        goto close;
    }

    if (len == 0) {
        warnx("client %s closed connection", c->addr);
        goto close;
    }

    c->magiclen += len;

    if (c->magiclen < sizeof(c->magic))
        return;

    m = alloca(sizeof(magic));

    if (1 != EVP_DecryptUpdate(c->ctx, m, &mlen, c->magic, c->magiclen)) {
        ERR_print_errors_fp(stderr);
        warnx("client %s closed due to ssl errors", c->addr);
        goto close;
    }

    if (mlen != sizeof(magic)) {
        warnx("client %s closed due to ssl failure", c->addr);
        goto close;
    }

    if (memcmp(m, magic, sizeof(magic))) {
        warnx("client %s closed due to bad magic", c->addr);
        goto close;
    }

    warnx("client %s authenticated", c->addr);

    curr = c;
    inlen = 0;
    event_del(&c->ev);
    event_assign(&c->ev, eb, fd, EV_READ | EV_TIMEOUT | EV_PERSIST, on_read, c);
    tv.tv_sec = READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(&c->ev, &tv);
    return;

    close:
    EVP_CIPHER_CTX_free(c->ctx);
    event_del(&c->ev);
    close(fd);
    free(c);
}


static void on_accept(int fd, short ev, void *arg)
{
    struct sockaddr_storage addr;
    struct timeval tv;
    struct client *c;
    uint8_t iv[16];
    socklen_t len;
    int client_fd;
    ssize_t ret;
    int ivlen;

    len = sizeof(addr);

    client_fd = accept4(fd, (struct sockaddr *)&addr, &len, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client_fd == -1) {
        warn("accept4(2)");
        return;
    }

    c = malloc(sizeof(struct client));
    if (c == NULL) {
        warnx("malloc(3): not enough memory");
        close(client_fd);
        return;
    }

    c->ctx = NULL;
    c->frame = NULL;
    c->magiclen = 0;

    if (addr.ss_family == AF_INET6) {
        char addrbuf[64];
        snprintf(c->addr, sizeof(c->addr), "[%s]:%d",
                 inet_ntop(AF_INET6, &(*((struct sockaddr_in6 *)&addr)).sin6_addr, addrbuf, sizeof(addrbuf)),
                 ntohs((*((struct sockaddr_in6 *)&addr)).sin6_port));
    } else if (addr.ss_family == AF_INET) {
        char addrbuf[32];
        snprintf(c->addr, sizeof(c->addr), "%s:%d",
                 inet_ntop(AF_INET, &(*((struct sockaddr_in *)&addr)).sin_addr, addrbuf, sizeof(addrbuf)),
                 ntohs((*((struct sockaddr_in *)&addr)).sin_port));
    } else
        strcpy(c->addr, "[UNKNOWN]");

    warnx("client %s connected", c->addr);

    for (ivlen = 0; ivlen < sizeof(iv);) {
        ssize_t r = getrandom(iv + ivlen, sizeof(iv) - ivlen, 0);

        if (r == -1) {
            if (errno == EINTR)
                continue;

            warn("getrandom(2)");
            free(c);
            close(client_fd);
            return;
        }

        ivlen += r;
    }

    ret = send(client_fd, iv, sizeof(iv), MSG_NOSIGNAL);

    if (ret < sizeof(iv)) {
        warn("send(2)");
        goto close;
    }

    c->ctx = EVP_CIPHER_CTX_new();
    if (c->ctx == NULL) {
        ERR_print_errors_fp(stderr);
        warnx("client %s closed due to ssl errors", c->addr);
        goto close;
    }

    if (1 != EVP_DecryptInit_ex(c->ctx, EVP_chacha20(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        warnx("client %s closed due to ssl errors", c->addr);
        goto close;
    }

    event_assign(&c->ev, eb, client_fd, EV_READ | EV_TIMEOUT | EV_PERSIST, on_read_verify, c);
    tv.tv_sec = READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(&c->ev, &tv);
    return;

    close:
    if (c->ctx)
        EVP_CIPHER_CTX_free(c->ctx);
    close(client_fd);
    free(c);
}


int main(int argc, char **argv)
{
    pthread_t thread;
    pthread_attr_t attr;
    struct event listen_ev;
    struct sockaddr_storage ss;
    size_t ss_size;
    int port = 0;
    int sock;

    char *addr = NULL;
    char *b64key = NULL;
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
            {"key", required_argument, NULL, 'k'},
            {NULL, 0, NULL, 0}
        };

        c = getopt_long(argc, argv, "ha:p:k:", long_options, &option_index);

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
                    warnx("bad port: %s", endptr);
                    usage(EXIT_FAILURE);
                }
                if (port < 1 || port > 65535) {
                    warnx("port out of range: %d", port);
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
        warnx("unknown argument: %s\n", argv[optind]);
        usage(EXIT_FAILURE);
    }

    if (addr == NULL || port == 0) {
        warnx("you should specify listen address and port");
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
        warnx("can't parse address: %s", addr);
        usage(EXIT_FAILURE);
    }

    /* create, bind and listen socket */
    sock = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (sock < 0)
        err(EXIT_FAILURE, "listen failed");

    c = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c)) == -1)
        err(EXIT_FAILURE, "setsockopt failed");

    if (bind(sock, (struct sockaddr *)&ss, ss_size) < 0)
        err(EXIT_FAILURE, "bind failed");

    if (listen(sock, 5) < 0)
        err(EXIT_FAILURE, "listen failed");

    /* initialize and set thread detached attribute */
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    /* start worker thread */
    c = pthread_create(&thread, &attr, worker, NULL);
    if (c)
        errx(EXIT_FAILURE, "pthread_create failed: %d", c);

    /* start listen loop */
    event_assign(&listen_ev, eb, sock, EV_READ | EV_PERSIST, on_accept, NULL);
    event_add(&listen_ev, NULL);

    /* event_base start */
    event_base_dispatch(eb);

    return 0;
}
