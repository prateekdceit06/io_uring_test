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

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek after hashing");
        goto cleanup;
    }

    result = 0;

cleanup:
    free(buffer);
    EVP_MD_CTX_free(ctx);
    return result;
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
    fprintf(stderr,
            "Usage: %s <server-ipv4> <input-file> [port]\n",
            program);
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *server_ip = argv[1];
    const char *input_path = argv[2];
    uint16_t port = DEFAULT_PORT;

    if (argc == 4 && parse_port(argv[3], &port) != 0) {
        fprintf(stderr, "Invalid port: %s\n", argv[3]);
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);

    int file_fd = -1;
    int socket_fd = -1;
    unsigned char *buffer = NULL;
    int exit_code = EXIT_FAILURE;

    file_fd = open(input_path, O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) {
        perror("open input file");
        goto cleanup;
    }

    struct stat file_info;
    if (fstat(file_fd, &file_info) < 0) {
        perror("fstat");
        goto cleanup;
    }

    if (!S_ISREG(file_info.st_mode) || file_info.st_size < 0) {
        fprintf(stderr, "Input must be a regular file\n");
        goto cleanup;
    }

    uint64_t file_size = (uint64_t)file_info.st_size;
    unsigned char original_hash[SHA256_SIZE];

    printf("Computing SHA-256 of %s...\n", input_path);
    if (sha256_fd(file_fd, original_hash) != 0) {
        goto cleanup;
    }

    printf("Original SHA-256: ");
    print_digest(original_hash);
    printf("File size: %" PRIu64 " bytes\n", file_size);

    socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0) {
        perror("socket");
        goto cleanup;
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(port);

    if (inet_pton(AF_INET, server_ip, &server_address.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", server_ip);
        goto cleanup;
    }

    printf("Connecting to %s:%u using blocking sockets...\n",
           server_ip, port);

    while (connect(socket_fd,
                   (struct sockaddr *)&server_address,
                   sizeof(server_address)) < 0) {
        if (errno == EINTR) {
            continue;
        }
        perror("connect");
        goto cleanup;
    }

    unsigned char header[HEADER_SIZE];
    memcpy(header, FILE_MAGIC, MAGIC_SIZE);

    uint64_t network_size = host_to_be64(file_size);
    memcpy(header + MAGIC_SIZE, &network_size, sizeof(network_size));
    memcpy(header + MAGIC_SIZE + sizeof(network_size),
           original_hash,
           SHA256_SIZE);

    if (send_all(socket_fd, header, sizeof(header)) != 0) {
        perror("send header");
        goto cleanup;
    }

    buffer = malloc(CHUNK_SIZE);
    if (buffer == NULL) {
        perror("malloc");
        goto cleanup;
    }

    uint64_t sent = 0;
    uint64_t next_report = PROGRESS_STEP;

    while (sent < file_size) {
        size_t wanted = CHUNK_SIZE;
        uint64_t remaining = file_size - sent;
        if (remaining < wanted) {
            wanted = (size_t)remaining;
        }

        ssize_t n;
        do {
            n = read(file_fd, buffer, wanted);
        } while (n < 0 && errno == EINTR);

        if (n < 0) {
            perror("read input file");
            goto cleanup;
        }
        if (n == 0) {
            fprintf(stderr,
                    "Unexpected EOF after %" PRIu64 " bytes\n",
                    sent);
            goto cleanup;
        }

        if (send_all(socket_fd, buffer, (size_t)n) != 0) {
            perror("send file data");
            goto cleanup;
        }

        sent += (uint64_t)n;
        print_progress("Sent", sent, file_size, &next_report);
    }

    unsigned char response[RESPONSE_SIZE];
    if (recv_all(socket_fd, response, sizeof(response)) != 0) {
        perror("receive verification response");
        goto cleanup;
    }

    unsigned char server_hash[SHA256_SIZE];
    memcpy(server_hash, response + 1, SHA256_SIZE);

    printf("Server SHA-256:   ");
    print_digest(server_hash);

    int local_match =
        memcmp(original_hash, server_hash, SHA256_SIZE) == 0;
    int server_match = response[0] == 1;

    if (local_match && server_match) {
        printf("VERIFIED: received file matches the original file.\n");
        exit_code = EXIT_SUCCESS;
    } else {
        fprintf(stderr, "VERIFICATION FAILED: SHA-256 mismatch.\n");
    }

cleanup:
    free(buffer);
    if (socket_fd >= 0) {
        close(socket_fd);
    }
    if (file_fd >= 0) {
        close(file_fd);
    }

    return exit_code;
}
