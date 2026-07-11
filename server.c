#include "common.h"

static void usage(const char *program) {
    fprintf(stderr, "Usage: %s [output-file] [port]\n", program);
}

int main(int argc, char **argv) {
    if (argc > 3) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *output_path = argc >= 2 ? argv[1] : "received.bin";
    uint16_t port = DEFAULT_PORT;

    if (argc == 3 && parse_port(argv[2], &port) != 0) {
        fprintf(stderr, "Invalid port: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    signal(SIGPIPE, SIG_IGN);

    int listen_fd = -1;
    int client_fd = -1;
    int output_fd = -1;
    struct io_uring ring;
    int ring_initialized = 0;
    unsigned char *buffer = NULL;
    int exit_code = EXIT_FAILURE;

    int rc = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    if (rc < 0) {
        errno = -rc;
        perror("io_uring_queue_init");
        goto cleanup;
    }
    ring_initialized = 1;

    listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        perror("socket");
        goto cleanup;
    }

    int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        goto cleanup;
    }

    struct sockaddr_in listen_address;
    memset(&listen_address, 0, sizeof(listen_address));
    listen_address.sin_family = AF_INET;
    listen_address.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_address.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&listen_address, sizeof(listen_address)) < 0) {
        perror("bind");
        goto cleanup;
    }

    if (listen(listen_fd, 128) < 0) {
        perror("listen");
        goto cleanup;
    }

    printf("Listening on 0.0.0.0:%u\n", port);
    printf("Output file: %s\n", output_path);

    struct sockaddr_in peer_address;
    socklen_t peer_length = sizeof(peer_address);
    memset(&peer_address, 0, sizeof(peer_address));

    client_fd = uring_accept_ipv4(&ring, listen_fd, &peer_address, &peer_length);
    if (client_fd < 0) {
        perror("io_uring accept");
        goto cleanup;
    }

    char peer_ip[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &peer_address.sin_addr, peer_ip, sizeof(peer_ip)) == NULL) {
        strcpy(peer_ip, "unknown");
    }
    printf("Client connected: %s:%u\n", peer_ip, ntohs(peer_address.sin_port));

    unsigned char header[HEADER_SIZE];
    if (uring_socket_read_all(&ring, client_fd, header, sizeof(header)) != 0) {
        perror("io_uring receive header");
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

        if (uring_socket_read_all(&ring, client_fd, buffer, chunk) != 0) {
            perror("io_uring receive file data");
            goto cleanup;
        }

        if (write_all_fd(output_fd, buffer, chunk) != 0) {
            perror("write output file");
            goto cleanup;
        }

        received += chunk;
        maybe_print_progress("Received", received, file_size, &next_report);
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

    int match = memcmp(original_hash, received_hash, SHA256_SIZE) == 0;

    unsigned char response[RESPONSE_SIZE];
    response[0] = match ? 1 : 0;
    memcpy(response + 1, received_hash, SHA256_SIZE);

    if (uring_socket_write_all(&ring, client_fd, response, sizeof(response)) != 0) {
        perror("io_uring send verification response");
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
    if (ring_initialized) {
        io_uring_queue_exit(&ring);
    }
    return exit_code;
}
