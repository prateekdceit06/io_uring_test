#include "common.h"

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s <server-ipv4> <input-file> [port]\n", program);
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
    struct io_uring ring;
    int ring_initialized = 0;
    unsigned char *buffer = NULL;
    int exit_code = EXIT_FAILURE;

    file_fd = open(input_path, O_RDONLY | O_CLOEXEC);
    if (file_fd < 0) {
        perror("open input file");
        goto cleanup;
    }

    struct stat st;
    if (fstat(file_fd, &st) < 0) {
        perror("fstat");
        goto cleanup;
    }
    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        fprintf(stderr, "Input must be a regular file\n");
        goto cleanup;
    }

    uint64_t file_size = (uint64_t)st.st_size;
    unsigned char original_hash[SHA256_SIZE];

    printf("Computing SHA-256 of %s...\n", input_path);
    if (sha256_fd(file_fd, original_hash) != 0) {
        goto cleanup;
    }

    printf("Original SHA-256: ");
    print_digest(original_hash);
    printf("File size: %" PRIu64 " bytes\n", file_size);

    int rc = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    if (rc < 0) {
        errno = -rc;
        perror("io_uring_queue_init");
        goto cleanup;
    }
    ring_initialized = 1;

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

    printf("Connecting to %s:%u using io_uring...\n", server_ip, port);
    if (uring_connect_ipv4(&ring, socket_fd, &server_address) != 0) {
        perror("io_uring connect");
        goto cleanup;
    }

    unsigned char header[HEADER_SIZE];
    memcpy(header, FILE_MAGIC, MAGIC_SIZE);

    uint64_t network_size = host_to_be64(file_size);
    memcpy(header + MAGIC_SIZE, &network_size, sizeof(network_size));
    memcpy(header + MAGIC_SIZE + sizeof(network_size), original_hash, SHA256_SIZE);

    if (uring_socket_write_all(&ring, socket_fd, header, sizeof(header)) != 0) {
        perror("io_uring send header");
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
            fprintf(stderr, "Unexpected EOF after %" PRIu64 " bytes\n", sent);
            goto cleanup;
        }

        if (uring_socket_write_all(&ring, socket_fd, buffer, (size_t)n) != 0) {
            perror("io_uring send file data");
            goto cleanup;
        }

        sent += (uint64_t)n;
        maybe_print_progress("Sent", sent, file_size, &next_report);
    }

    unsigned char response[RESPONSE_SIZE];
    if (uring_socket_read_all(&ring, socket_fd, response, sizeof(response)) != 0) {
        perror("io_uring receive verification response");
        goto cleanup;
    }

    unsigned char server_hash[SHA256_SIZE];
    memcpy(server_hash, response + 1, SHA256_SIZE);

    printf("Server SHA-256:   ");
    print_digest(server_hash);

    int local_match = memcmp(original_hash, server_hash, SHA256_SIZE) == 0;
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
    if (ring_initialized) {
        io_uring_queue_exit(&ring);
    }
    if (file_fd >= 0) {
        close(file_fd);
    }
    return exit_code;
}
