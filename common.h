#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <liburing.h>
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
#include <sys/uio.h>
#include <unistd.h>

#define DEFAULT_PORT 9090
#define QUEUE_DEPTH 64
#define CHUNK_SIZE (128U * 1024U)
#define SHA256_SIZE 32U
#define MAGIC_SIZE 8U
#define HEADER_SIZE (MAGIC_SIZE + 8U + SHA256_SIZE)
#define RESPONSE_SIZE (1U + SHA256_SIZE)
#define PROGRESS_STEP (100ULL * 1024ULL * 1024ULL)

static const unsigned char FILE_MAGIC[MAGIC_SIZE] = {
    'U', 'R', 'I', 'N', 'G', 'F', '0', '1'
};

static inline uint64_t host_to_be64(uint64_t value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(value & 0xffffffffULL)) << 32) |
           htonl((uint32_t)(value >> 32));
#else
    return value;
#endif
}

static inline uint64_t be64_to_host(uint64_t value) {
    return host_to_be64(value);
}

static inline void print_digest(const unsigned char digest[SHA256_SIZE]) {
    for (size_t i = 0; i < SHA256_SIZE; ++i) {
        printf("%02x", digest[i]);
    }
    putchar('\n');
}

static inline int parse_port(const char *text, uint16_t *port_out) {
    char *end = NULL;
    errno = 0;
    long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 1 || value > 65535) {
        return -1;
    }
    *port_out = (uint16_t)value;
    return 0;
}

static inline int sha256_fd(int fd, unsigned char digest[SHA256_SIZE]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char *buffer = NULL;
    int rc = -1;

    if (ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        return -1;
    }

    buffer = malloc(CHUNK_SIZE);
    if (buffer == NULL) {
        perror("malloc");
        goto out;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek before hashing");
        goto out;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        goto out;
    }

    for (;;) {
        ssize_t n = read(fd, buffer, CHUNK_SIZE);
        if (n > 0) {
            if (EVP_DigestUpdate(ctx, buffer, (size_t)n) != 1) {
                fprintf(stderr, "EVP_DigestUpdate failed\n");
                goto out;
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
        goto out;
    }

    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != SHA256_SIZE) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        goto out;
    }

    if (lseek(fd, 0, SEEK_SET) < 0) {
        perror("lseek after hashing");
        goto out;
    }

    rc = 0;
out:
    free(buffer);
    EVP_MD_CTX_free(ctx);
    return rc;
}

static inline int sha256_path(const char *path, unsigned char digest[SHA256_SIZE]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        perror("open file for hashing");
        return -1;
    }

    int rc = sha256_fd(fd, digest);
    close(fd);
    return rc;
}

static inline int write_all_fd(int fd, const void *buffer, size_t length) {
    const unsigned char *ptr = buffer;
    size_t remaining = length;

    while (remaining > 0) {
        ssize_t n = write(fd, ptr, remaining);
        if (n > 0) {
            ptr += (size_t)n;
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

static inline int uring_submit_and_wait(struct io_uring *ring) {
    int submitted = io_uring_submit(ring);
    if (submitted < 0) {
        return submitted;
    }
    if (submitted == 0) {
        return -EIO;
    }

    struct io_uring_cqe *cqe = NULL;
    int rc = io_uring_wait_cqe(ring, &cqe);
    if (rc < 0) {
        return rc;
    }

    int result = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    return result;
}

/*
 * Envoy's io_uring worker submits readv/writev requests for TCP sockets.
 * These helpers use the same operation family and handle partial completion.
 */
static inline int uring_socket_write_all(struct io_uring *ring,
                                         int socket_fd,
                                         const void *buffer,
                                         size_t length) {
    const unsigned char *ptr = buffer;
    size_t remaining = length;

    while (remaining > 0) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (sqe == NULL) {
            errno = EBUSY;
            return -1;
        }

        struct iovec iov = {
            .iov_base = (void *)ptr,
            .iov_len = remaining,
        };

        io_uring_prep_writev(sqe, socket_fd, &iov, 1, 0);
        int result = uring_submit_and_wait(ring);

        if (result > 0) {
            ptr += (size_t)result;
            remaining -= (size_t)result;
            continue;
        }
        if (result == -EINTR || result == -EAGAIN) {
            continue;
        }

        errno = result < 0 ? -result : EPIPE;
        return -1;
    }

    return 0;
}

static inline int uring_socket_read_all(struct io_uring *ring,
                                        int socket_fd,
                                        void *buffer,
                                        size_t length) {
    unsigned char *ptr = buffer;
    size_t remaining = length;

    while (remaining > 0) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (sqe == NULL) {
            errno = EBUSY;
            return -1;
        }

        struct iovec iov = {
            .iov_base = ptr,
            .iov_len = remaining,
        };

        io_uring_prep_readv(sqe, socket_fd, &iov, 1, 0);
        int result = uring_submit_and_wait(ring);

        if (result > 0) {
            ptr += (size_t)result;
            remaining -= (size_t)result;
            continue;
        }
        if (result == -EINTR || result == -EAGAIN) {
            continue;
        }

        errno = result < 0 ? -result : ECONNRESET;
        return -1;
    }

    return 0;
}

static inline int uring_connect_ipv4(struct io_uring *ring,
                                     int socket_fd,
                                     const struct sockaddr_in *address) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe == NULL) {
        errno = EBUSY;
        return -1;
    }

    io_uring_prep_connect(sqe,
                          socket_fd,
                          (const struct sockaddr *)address,
                          sizeof(*address));

    int result = uring_submit_and_wait(ring);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return 0;
}

static inline int uring_accept_ipv4(struct io_uring *ring,
                                    int listen_fd,
                                    struct sockaddr_in *peer,
                                    socklen_t *peer_length) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe == NULL) {
        errno = EBUSY;
        return -1;
    }

    io_uring_prep_accept(sqe,
                         listen_fd,
                         (struct sockaddr *)peer,
                         peer_length,
                         SOCK_CLOEXEC);

    int result = uring_submit_and_wait(ring);
    if (result < 0) {
        errno = -result;
        return -1;
    }
    return result;
}

static inline void maybe_print_progress(const char *label,
                                        uint64_t completed,
                                        uint64_t total,
                                        uint64_t *next_report) {
    if (completed < *next_report && completed != total) {
        return;
    }

    double percent = total == 0 ? 100.0 : (100.0 * (double)completed / (double)total);
    printf("\r%s: %" PRIu64 " / %" PRIu64 " bytes (%.1f%%)",
           label,
           completed,
           total,
           percent);
    fflush(stdout);

    while (*next_report <= completed) {
        *next_report += PROGRESS_STEP;
    }
    if (completed == total) {
        putchar('\n');
    }
}

#endif
