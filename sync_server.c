#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEFAULT_PORT 9090
#define CHUNK_SIZE (128U * 1024U)
#define SHA256_SIZE 32U
#define MAGIC_SIZE 8U
#define HEADER_SIZE (MAGIC_SIZE + 8U + SHA256_SIZE)
#define RESPONSE_SIZE (1U + SHA256_SIZE)
#define PROGRESS_STEP (100ULL * 1024ULL * 1024ULL)

static const unsigned char FILE_MAGIC[MAGIC_SIZE] = {
    'U', 'R', 'I', 'N', 'G', 'F', '0', '1'
};

static uint64_t host_to_be64(uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(value & 0xffffffffULL)) << 32) |
           htonl((uint32_t)(value >> 32));
#else
    return value;
#endif
}

static uint64_t be64_to_host(uint64_t value) {
    return host_to_be64(value);
}

static void print_digest(const unsigned char digest[SHA256_SIZE]) {
    for (size_t i = 0; i < SHA256_SIZE; ++i) {
        printf("%02x", digest[i]);
    }
    putchar('\n');
}

static int parse_port(const char *text, uint16_t *port_out) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0' ||
        value < 1 || value > 65535) {
        return -1;
    }

    *port_out = (uint16_t)value;
    return 0;
}

static int sha256_fd(int fd, unsigned char digest[SHA256_SIZE]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *buffer = NULL;
    int result = -1;

    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return -1;
    }

    buffer = malloc(CHUNK_SIZE);
    if (buffer == NULL) {
        perror("malloc");
        goto cleanup;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek before hashing");
        goto cleanup;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        goto cleanup;
    }

    for (;;) {
        ssize_t n = read(fd, buffer, CHUNK_SIZE);
        if (n > 0) {
            if (EVP_DigestUpdate(ctx, buffer, (size_t)n) != 1) {
                fprintf(stderr, "EVP_DigestUpdate failed\n");
                goto cleanup;
            }
            continue;
        }
        if (n == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }

        perror("read while hashing");
        goto cleanup;
    }

    unsigned int digest_length = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_length) != 1 ||
        digest_length != SHA256_SIZE) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        goto cleanup;
    }

    result = 0;

cleanup:
    free(buffer);
    EVP_MD_CTX_free(ctx);
    return result;
}

static int sha256_path(const char *path,
                       unsigned char digest[SHA256_SIZE]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open file for hashing");
        return -1;
    }

    int result = sha256_fd(fd, digest);
    close(fd);
    return result;
}

static int write_all_fd(int fd, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    size_t remaining = length;

    while (remaining > 0) {
        ssize_t n = write(fd, cursor, remaining);
        if (n > 0) {
            cursor += (size_t)n;
            remaining -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n == 0) {
            errno = EIO;
        }
        return -1;
    }

    return 0;
}

static int send_all(int socket_fd, const void *buffer, size_t length) {
    const unsigned char *cursor = buffer;
    size_t remaining = length;

    while (remaining > 0) {
        ssize_t n = send(socket_fd, cursor, remaining, 0);
        if (n > 0) {
            cursor += (size_t)n;
            remaining -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n == 0) {
            errno = EPIPE;
        }
        return -1;
    }

    return 0;
}

static int recv_all(int socket_fd, void *buffer, size_t length) {
    unsigned char *cursor = buffer;
    size_t remaining = length;

    while (remaining > 0) {
        ssize_t n = recv(socket_fd, cursor, remaining, 0);
        if (n > 0) {
            cursor += (size_t)n;
            remaining -= (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n == 0) {
            errno = ECONNRESET;
        }
        return -1;
    }

    return 0;
}

static void print_progress(const char *label,
                           uint64_t completed,
                           uint64_t total,
                           uint64_t *next_report) {
    if (completed < *next_report && completed != total) {
        return;
    }

    double percent = total == 0
                         ? 100.0
                         : 100.0 * (double)completed / (double)total;

    printf("\r%s: %" PRIu64 " / %" PRIu64 " bytes (%.1f%%)",
           label, completed, total, percent);
    fflush(stdout);

    while (*next_report <= completed) {
        *next_report += PROGRESS_STEP;
    }

    if (completed == total) {
        putchar('\n');
    }
}

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s [output-file] [port]\n", program);
}

int main(int argc, char **argv) {
    if (argc > 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *output_path = argc >= 2 ? argv[1] : "sync_received.bin";
    uint16_t port = DEFAULT_PORT;

    if (argc == 3 && parse_port(argv[2], &port) != 0) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);

    int listen_fd = -1;
    int client_fd = -1;
    int output_fd = -1;
    unsigned char *buffer = NULL;
    int exit_code = EXIT_FAILURE;

    listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        perror("socket");
        goto cleanup;
    }

    int reuse = 1;
    if (setsockopt(listen_fd,
                   SOL_SOCKET,
                   SO_REUSEADDR,
                   &reuse,
                   sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        goto cleanup;
    }

    struct sockaddr_in listen_address;
    memset(&listen_address, 0, sizeof(listen_address));
    listen_address.sin_family = AF_INET;
    listen_address.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_address.sin_port = htons(port);

    if (bind(listen_fd,
             (struct sockaddr *)&listen_address,
             sizeof(listen_address)) < 0) {
        perror("bind");
        goto cleanup;
    }

    if (listen(listen_fd, 128) < 0) {
        perror("listen");
        goto cleanup;
    }

    printf("Listening on 0.0.0.0:%u using blocking sockets\n", port);
    printf("Output file: %s\n", output_path);

    struct sockaddr_in peer_address;
    socklen_t peer_length = sizeof(peer_address);
    memset(&peer_address, 0, sizeof(peer_address));

    do {
        client_fd = accept(listen_fd,
                           (struct sockaddr *)&peer_address,
                           &peer_length);
    } while (client_fd < 0 && errno == EINTR);

    if (client_fd < 0) {
        perror("accept");
        goto cleanup;
    }

    char peer_ip[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET,
                  &peer_address.sin_addr,
                  peer_ip,
                  sizeof(peer_ip)) == NULL) {
        strcpy(peer_ip, "unknown");
    }

    printf("Client connected: %s:%u\n",
           peer_ip,
           ntohs(peer_address.sin_port));

    unsigned char header[HEADER_SIZE];
    if (recv_all(client_fd, header, sizeof(header)) != 0) {
        perror("receive header");
        goto cleanup;
    }

    if (memcmp(header, FILE_MAGIC, MAGIC_SIZE) != 0) {
        fprintf(stderr, "Invalid protocol magic\n");
        goto cleanup;
    }

    uint64_t network_size;
    memcpy(&network_size, header + MAGIC_SIZE, sizeof(network_size));
    uint64_t file_size = be64_to_host(network_size);

    unsigned char original_hash[SHA256_SIZE];
    memcpy(original_hash,
           header + MAGIC_SIZE + sizeof(network_size),
           SHA256_SIZE);

    printf("Expected file size: %" PRIu64 " bytes\n", file_size);
    printf("Client SHA-256:   ");
    print_digest(original_hash);

    output_fd = open(output_path,
                     O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                     0644);
    if (output_fd < 0) {
        perror("open output file");
        goto cleanup;
    }

    buffer = malloc(CHUNK_SIZE);
    if (buffer == NULL) {
        perror("malloc");
        goto cleanup;
    }

    uint64_t received = 0;
    uint64_t next_report = PROGRESS_STEP;

    while (received < file_size) {
        size_t chunk = CHUNK_SIZE;
        uint64_t remaining = file_size - received;
        if (remaining < chunk) {
            chunk = (size_t)remaining;
        }

        if (recv_all(client_fd, buffer, chunk) != 0) {
            perror("receive file data");
            goto cleanup;
        }

        if (write_all_fd(output_fd, buffer, chunk) != 0) {
            perror("write output file");
            goto cleanup;
        }

        received += chunk;
        print_progress("Received",
                       received,
                       file_size,
                       &next_report);
    }

    if (fsync(output_fd) < 0) {
        perror("fsync output file");
        goto cleanup;
    }

    if (close(output_fd) < 0) {
        perror("close output file");
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;

    unsigned char received_hash[SHA256_SIZE];
    printf("Computing SHA-256 of received file...\n");
    if (sha256_path(output_path, received_hash) != 0) {
        goto cleanup;
    }

    printf("Received SHA-256: ");
    print_digest(received_hash);

    int match =
        memcmp(original_hash, received_hash, SHA256_SIZE) == 0;

    unsigned char response[RESPONSE_SIZE];
    response[0] = match ? 1 : 0;
    memcpy(response + 1, received_hash, SHA256_SIZE);

    if (send_all(client_fd, response, sizeof(response)) != 0) {
        perror("send verification response");
        goto cleanup;
    }

    if (match) {
        printf("VERIFIED: received file matches the original file.\n");
        exit_code = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "VERIFICATION FAILED: SHA-256 mismatch.\n");
    }

cleanup:
    free(buffer);
    if (output_fd >= 0) {
        close(output_fd);
    }
    if (client_fd >= 0) {
        close(client_fd);
    }
    if (listen_fd >= 0) {
        close(listen_fd);
    }

    return exit_code;
}
