# io_uring vs Synchronous TCP File Transfer

This project contains two TCP file-transfer implementations:

- **io_uring version:** `client` and `server`
- **Synchronous version:** `sync_client` and `sync_server`

Both versions:

- Transfer a file in 128 KiB chunks
- Use synchronous `read()` and `write()` for local file I/O
- Calculate SHA-256
- Verify that the received file matches the original
- Correctly handle partial TCP reads and writes

The only intended difference is the socket communication:

| Version | Socket operations |
|---|---|
| io_uring | `io_uring` connect, accept, read and write |
| Synchronous | Blocking `connect()`, `accept()`, `send()` and `recv()` |

## Project Files

```text
client.c
server.c
common.h
sync_client.c
sync_server.c
Makefile
README.md
```

## Requirements

This project requires Linux.

Recommended:

```text
Linux kernel 5.11 or newer
```

Ubuntu 22.04 LTS or newer is suitable.

Check your system:

```bash
uname -r
uname -m
```

Check whether `io_uring` is disabled:

```bash
cat /proc/sys/kernel/io_uring_disabled
```

Expected value:

```text
0
```

`0` means `io_uring` is enabled.

## Install Dependencies

On Ubuntu:

```bash
sudo apt update
sudo apt install -y git build-essential liburing-dev libssl-dev time
```

## Clone the Repository

```bash
git clone https://github.com/prateekdceit06/io_uring_test.git
cd io_uring_test
```

## Build

Build both implementations:

```bash
make
```

This creates:

```text
client
server
sync_client
sync_server
```

Build only the `io_uring` version:

```bash
make uring
```

Build only the synchronous version:

```bash
make sync
```

Remove generated binaries and received files:

```bash
make clean
```

Show available Makefile targets:

```bash
make help
```

## Create a 1 GiB Test File

```bash
fallocate -l 1G 1gb.bin
```

Confirm the file size:

```bash
ls -lh 1gb.bin
```

A random-data file can also be created:

```bash
dd if=/dev/urandom of=1gb.bin bs=1M count=1024 status=progress
```

## Run the io_uring Version

Open two terminals.

### Terminal 1

```bash
cd ~/io_uring_test
./server received.bin 9090
```

### Terminal 2

```bash
cd ~/io_uring_test
./client 127.0.0.1 1gb.bin 9090
```

A successful transfer prints:

```text
VERIFIED: received file matches the original file.
```

## Run the Synchronous Version

Open two terminals.

### Terminal 1

```bash
cd ~/io_uring_test
./sync_server sync_received.bin 9091
```

### Terminal 2

```bash
cd ~/io_uring_test
./sync_client 127.0.0.1 1gb.bin 9091
```

Port `9091` is used to avoid a conflict with the `io_uring` example on port `9090`.

## Verify the Received Files

Check SHA-256 hashes:

```bash
sha256sum 1gb.bin received.bin sync_received.bin
```

All three hashes should match.

Perform byte-for-byte checks:

```bash
cmp 1gb.bin received.bin
cmp 1gb.bin sync_received.bin
```

No output from `cmp` means the files are identical.

## Compare Execution Time

Start the relevant server before running each client.

### io_uring Client

```bash
/usr/bin/time -f "io_uring elapsed: %e seconds" \
    ./client 127.0.0.1 1gb.bin 9090
```

### Synchronous Client

```bash
/usr/bin/time -f "synchronous elapsed: %e seconds" \
    ./sync_client 127.0.0.1 1gb.bin 9091
```

Run each version several times and compare the median.

The server exits after one transfer, so restart it before every client run.

## Confirm io_uring Is Being Used

Install `strace`:

```bash
sudo apt install -y strace
```

Trace the `io_uring` server:

```bash
strace -f \
    -e trace=io_uring_setup,io_uring_enter,io_uring_register \
    ./server received.bin 9090
```

Run the client in another terminal:

```bash
./client 127.0.0.1 1gb.bin 9090
```

The trace should show calls such as:

```text
io_uring_setup(...)
io_uring_enter(...)
```

The synchronous programs should not issue these `io_uring` system calls.

## Important Comparison Note

The current `io_uring` implementation submits one socket operation and waits for its completion before submitting the next operation.

Because it does not keep multiple operations in flight, it may not be faster than the synchronous version. Larger benefits generally require concurrency, batching, or several in-flight operations.

## Common Errors

### `liburing.h: No such file or directory`

```bash
sudo apt install -y liburing-dev
```

### `openssl/evp.h: No such file or directory`

```bash
sudo apt install -y libssl-dev
```

### `io_uring_queue_init: Function not implemented`

Check the kernel:

```bash
uname -r
```

Use Linux 5.11 or newer.

### `io_uring_queue_init: Operation not permitted`

Check:

```bash
cat /proc/sys/kernel/io_uring_disabled
```

A value of `0` means enabled.

### `Connection refused`

Start the correct server first and make sure the client uses the same port.

### `Address already in use`

Use a different port on both sides:

```bash
./server received.bin 9092
./client 127.0.0.1 1gb.bin 9092
```

## Notes

- Both servers handle one client and then exit.
- Both versions use IPv4.
- File I/O is synchronous in both versions.
- Only the network socket mechanism differs.
- This is a learning and comparison project, not a production file-transfer service.
