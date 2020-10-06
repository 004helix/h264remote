CC = gcc
LD = gcc
CFLAGS = -Wall
#CFLAGS = -Wall -g
SEND_LDFLAGS = -levent_core -lcrypto
FEED_LDFLAGS = -levent_core -lcrypto -lpthread

SRC = $(wildcard *.c)
OBJ = $(patsubst %.c,build/%.o,$(SRC))

all: h264send h264feed

h264send: build/h264send.o
	$(LD) -o $@ build/h264send.o $(SEND_LDFLAGS)

h264feed: build/h264feed.o
	$(LD) -o $@ build/h264feed.o $(FEED_LDFLAGS)

-include $(OBJ:.o=.d)

$(OBJ): build/%.o : %.c
	$(CC) $(CFLAGS) -c $< -o build/$*.o
	@$(CC) $(CFLAGS) -MM $< -MF build/$*.d
	@sed -i build/$*.d -e 's,\($*\)\.o[ :]*,build/\1.o: ,g'

clean:
	rm -rf $(EXE) build/*.o build/*.d
