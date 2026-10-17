/* OpenPGP v4 fingerprint search.

   The preimage is 0x99 || 2-byte length || public key body. The four-byte
   big-endian creation time starts at offset 4. The key id is the last
   eight bytes of SHA-1(preimage). A hit is a key id whose first `leading`
   bytes are the same doubled nibble (0x00, 0x11, ... 0xFF).

   The buffer passed to pgpgen_search is not modified. The scan starts at
   the creation time already stored in the preimage and steps backward one
   second at a time.
*/
#include <errno.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static int read_full(int fd, uint8_t *dst, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, dst + got, n - got);
        if (r == 0) {
            return got == 0 ? 0 : -1;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        got += (size_t)r;
    }
    return 1;
}

static uint16_t read_be16(const uint8_t in[2]) {
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t read_be32(const uint8_t in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static void write_be32(uint8_t out[4], uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static int digest_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    unsigned int out_len = 0;
    if (EVP_Digest(data, len, out, &out_len, EVP_sha1(), NULL) != 1) {
        return -1;
    }
    return out_len == 20 ? 0 : -1;
}

static int leading_match(const uint8_t hash[20], unsigned leading) {
    const uint8_t *key_id = hash + 12;
    uint8_t first = key_id[0];
    if ((first >> 4) != (first & 0x0f)) {
        return 0;
    }
    for (unsigned i = 1; i < leading; i++) {
        if (key_id[i] != first) {
            return 0;
        }
    }
    return 1;
}

/* Newest matching unix time, or -1. *checked receives attempts performed. */
static int64_t pgpgen_search(const uint8_t *src, size_t len, size_t time_off,
                             uint32_t max_iter, unsigned leading, uint64_t *checked) {
    if (checked != NULL) {
        *checked = 0;
    }
    if (src == NULL || len < 4 || time_off > len - 4 || max_iter == 0 ||
        leading == 0 || leading > 8) {
        return -1;
    }

    uint8_t *buf = malloc(len);
    if (buf == NULL) {
        return -1;
    }
    memcpy(buf, src, len);

    uint32_t start = read_be32(buf + time_off);
    int64_t found = -1;
    uint64_t room = (uint64_t)start + 1;
    uint32_t limit = max_iter;
    if ((uint64_t)limit > room) {
        limit = room > 0xffffffffu ? 0xffffffffu : (uint32_t)room;
    }

    for (uint32_t i = 0; i < limit; i++) {
        uint32_t stamp = start - i;
        write_be32(buf + time_off, stamp);
        uint8_t hash[20];
        if (digest_sha1(buf, len, hash) != 0) {
            free(buf);
            return -1;
        }
        if (checked != NULL) {
            *checked = (uint64_t)i + 1;
        }
        if (leading_match(hash, leading)) {
            found = (int64_t)stamp;
            break;
        }
    }

    free(buf);
    return found;
}

static int cmd_self_test(void) {
    static const char message[] = "pgpgen-sha1-selftest";
    uint8_t hash[20];
    if (digest_sha1((const uint8_t *)message, sizeof message - 1, hash) != 0) {
        fprintf(stderr, "pgpgen-accel: SHA-1 self-test failed\n");
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 20; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    return EXIT_SUCCESS;
}

static int cmd_digest(void) {
    uint8_t *buf = NULL;
    size_t len = 0;
    uint8_t tmp[4096];
    for (;;) {
        ssize_t r = read(STDIN_FILENO, tmp, sizeof tmp);
        if (r == 0) {
            break;
        }
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(buf);
            fprintf(stderr, "pgpgen-accel: reading digest input failed\n");
            return EXIT_FAILURE;
        }
        uint8_t *grown = realloc(buf, len + (size_t)r);
        if (grown == NULL) {
            free(buf);
            fprintf(stderr, "pgpgen-accel: out of memory\n");
            return EXIT_FAILURE;
        }
        buf = grown;
        memcpy(buf + len, tmp, (size_t)r);
        len += (size_t)r;
    }
    uint8_t hash[20];
    int rc = digest_sha1(buf, len, hash);
    free(buf);
    if (rc != 0) {
        fprintf(stderr, "pgpgen-accel: SHA-1 digest failed\n");
        return EXIT_FAILURE;
    }
    for (int i = 0; i < 20; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
    return EXIT_SUCCESS;
}

static void reject(const char *msg) {
    fprintf(stderr, "pgpgen-accel: %s\n", msg);
    printf("-1\n0\n");
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    /* Stop if the Python worker that spawned us is gone. */
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) {
        perror("pgpgen-accel");
        return EXIT_FAILURE;
    }
    if (getppid() == 1) {
        return EXIT_FAILURE;
    }
    if (argc == 2 && strcmp(argv[1], "--self-test") == 0) {
        return cmd_self_test();
    }
    if (argc == 2 && strcmp(argv[1], "--digest") == 0) {
        return cmd_digest();
    }
    if (argc != 1) {
        fprintf(stderr, "usage: %s [--self-test|--digest]\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint8_t *preimage = NULL;
    uint16_t preimage_len = 0;
    uint16_t time_off = 0;
    uint32_t max_iter = 0;
    uint16_t leading = 0;
    int saw_preimage = 0;
    int saw_offset = 0;
    int saw_limit = 0;
    int saw_leading = 0;

    for (;;) {
        uint8_t hdr[3];
        int rc = read_full(STDIN_FILENO, hdr, 3);
        if (rc == 0) {
            break;
        }
        if (rc < 0) {
            reject("short TLV header");
        }
        uint8_t tag = hdr[0];
        uint16_t len = read_be16(hdr + 1);
        uint8_t *body = NULL;
        if (len > 0) {
            body = malloc(len);
            if (body == NULL) {
                reject("out of memory");
            }
            if (read_full(STDIN_FILENO, body, len) != 1) {
                free(body);
                reject("short TLV value");
            }
        }

        switch (tag) {
        case 0x01:
            free(preimage);
            preimage = body;
            preimage_len = len;
            saw_preimage = 1;
            body = NULL;
            break;
        case 0x02:
            if (len != 2) {
                free(body);
                reject("time offset must be 2 bytes");
            }
            time_off = read_be16(body);
            saw_offset = 1;
            break;
        case 0x03:
            if (len != 4) {
                free(body);
                reject("iteration count must be 4 bytes");
            }
            max_iter = read_be32(body);
            saw_limit = 1;
            break;
        case 0x04:
            if (len != 2) {
                free(body);
                reject("leading length must be 2 bytes");
            }
            leading = read_be16(body);
            saw_leading = 1;
            break;
        default:
            free(body);
            reject("unknown TLV tag");
        }
        free(body);
    }

    if (!saw_preimage || !saw_offset || !saw_limit || !saw_leading) {
        reject("incomplete search request");
    }
    if (preimage_len < 4 || time_off > (uint16_t)(preimage_len - 4)) {
        reject("time offset is outside the preimage");
    }

    uint64_t checked = 0;
    int64_t found = pgpgen_search(preimage, preimage_len, time_off, max_iter, leading, &checked);
    free(preimage);
    if (found < 0 && checked == 0 && max_iter != 0) {
        /* pgpgen_search rejects an empty or inverted request before hashing. */
        reject("search arguments were rejected");
    }
    if (found < 0) {
        printf("-1\n%" PRIu64 "\n", checked);
        return EXIT_SUCCESS;
    }
    printf("%" PRIu64 "\n%" PRIu64 "\n", (uint64_t)found, checked);
    return EXIT_SUCCESS;
}
