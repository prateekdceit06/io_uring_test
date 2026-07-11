CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11

URING_LIBS := -luring -lcrypto
SYNC_LIBS  := -lcrypto

URING_BINS := client server
SYNC_BINS  := sync_client sync_server
BINARIES   := $(URING_BINS) $(SYNC_BINS)

.PHONY: all uring sync clean help

all: uring sync

uring: $(URING_BINS)

sync: $(SYNC_BINS)

client: client.c common.h
	$(CC) $(CFLAGS) client.c -o $@ $(URING_LIBS)

server: server.c common.h
	$(CC) $(CFLAGS) server.c -o $@ $(URING_LIBS)

sync_client: sync_client.c
	$(CC) $(CFLAGS) sync_client.c -o $@ $(SYNC_LIBS)

sync_server: sync_server.c
	$(CC) $(CFLAGS) sync_server.c -o $@ $(SYNC_LIBS)

clean:
	rm -f $(BINARIES)
	rm -f received.bin sync_received.bin

help:
	@echo "Targets:"
	@echo "  make         Build both io_uring and synchronous versions"
	@echo "  make uring   Build client and server"
	@echo "  make sync    Build sync_client and sync_server"
	@echo "  make clean   Remove binaries and received output files"
