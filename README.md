# io_uring TCP File Transfer

A simple client-server project that transfers a file over TCP using Linux `io_uring` for network communication.

- Client sends a file to the server.
- Server writes the received file to disk.
- Both sides calculate SHA-256.
- The client verifies that the received file matches the original.

## What Uses `io_uring`

`io_uring` is used for TCP socket operations:

- `connect`
- `accept`
- socket reads
- socket writes

Regular POSIX calls are used for file operations:

- `open`
- `read`
- `write`
- `close`

This follows the same general approach as Envoy's `io_uring` networking support.

## Requirements

This project requires Linux. It does not run directly on macOS.

You can run it inside:

- Ubuntu on UTM
- Another Linux virtual machine
- A Linux cloud machine
- A physical Linux machine

### Linux kernel

Recommended:

```text
Linux 5.11 or newer
```

Ubuntu 22.04 LTS or newer is suitable.

Check your kernel:

```bash
uname -r
```

Example compatible output:

```text
5.15.0-xxx-generic
```

Check the architecture:

```bash
uname -m
```

Common outputs:

```text
x86_64
aarch64
```

Check whether `io_uring` is disabled:

```bash
cat /proc/sys/kernel/io_uring_disabled
```

Expected value:

```text
0
```

If the file does not exist, continue and test the program directly.

## Install Dependencies

On Ubuntu:

```bash
sudo apt update
sudo apt install -y git build-essential liburing-dev libssl-dev
```

## Clone the Repository

```bash
git clone https://github.com/prateekdceit06/io_uring_test.git
cd io_uring_test
```

## Build

```bash
make
```

This creates:

```text
client
server
```

Clean the build:

```bash
make clean
```

## Create a 1 GiB Test File

Fast zero-filled file:

```bash
fallocate -l 1G 1gb.bin
```

Or create a random file:

```bash
dd if=/dev/urandom of=1gb.bin bs=1M count=1024 status=progress
```

Check available disk space first:

```bash
df -h .
```

You need space for both the original file and the received copy.

## Run on One Linux Machine

Open two terminals inside the Linux machine.

### Terminal 1: Start the Server

```bash
./server received.bin 9090
```

Syntax:

```text
./server [output-file] [port]
```

Defaults:

```text
output-file: received.bin
port: 9090
```

You can also run:

```bash
./server
```

### Terminal 2: Start the Client

```bash
./client 127.0.0.1 1gb.bin 9090
```

Syntax:

```text
./client <server-ip> <input-file> [port]
```

The port defaults to `9090`.

## Verify the Transfer

The client should print:

```text
VERIFIED: received file matches the original file.
```

You can also verify manually:

```bash
sha256sum 1gb.bin received.bin
```

Both hashes should match.

Byte-for-byte verification:

```bash
cmp 1gb.bin received.bin
```

No output means the files are identical.

## Run Between Two Linux Machines

On the server machine:

```bash
./server received.bin 9090
```

Find the server IP:

```bash
hostname -I
```

On the client machine:

```bash
./client SERVER_IP 1gb.bin 9090
```

If the firewall is enabled on the server:

```bash
sudo ufw allow 9090/tcp
```

## Confirm `io_uring` Is Being Used

Install `strace`:

```bash
sudo apt install -y strace
```

Trace the server:

```bash
strace -f -e trace=io_uring_setup,io_uring_enter,io_uring_register \
    ./server received.bin 9090
```

Then run the client in another terminal.

You should see calls such as:

```text
io_uring_setup(...)
io_uring_enter(...)
```

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

The Linux kernel is too old or lacks `io_uring` support.

Check:

```bash
uname -r
```

Use Linux 5.11 or newer.

### `io_uring_queue_init: Operation not permitted`

`io_uring` may be disabled or restricted.

Check:

```bash
cat /proc/sys/kernel/io_uring_disabled
```

A value of `0` means enabled.

### `Connection refused`

Start the server first and confirm both programs use the same port.

```bash
./server received.bin 9090
./client 127.0.0.1 1gb.bin 9090
```

### `Address already in use`

Use another port:

```bash
./server received.bin 9091
./client 127.0.0.1 1gb.bin 9091
```

## Notes

- The server handles one client and then exits.
- The project uses IPv4.
- File reads and writes are synchronous.
- Socket communication uses `io_uring`.
- The code handles partial TCP reads and writes.
- This is a learning project, not a production file-transfer service.

## References

- [Envoy io_uring documentation](https://www.envoyproxy.io/docs/envoy/latest/configuration/other_features/io_uring)
- [Envoy repository](https://github.com/envoyproxy/envoy)
- [liburing repository](https://github.com/axboe/liburing)
- [io_uring manual page](https://man7.org/linux/man-pages/man7/io_uring.7.html)
