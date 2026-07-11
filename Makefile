CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11
LDLIBS = -luring -lcrypto

.PHONY: all clean

all: server client

server: server.c common.h
	$(CC) $(CFLAGS) server.c -o server $(LDLIBS)

client: client.c common.h
	$(CC) $(CFLAGS) client.c -o client $(LDLIBS)

clean:
	rm -f server client received.bin
