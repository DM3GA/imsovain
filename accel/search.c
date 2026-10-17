#include "search.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

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

int pgpgen_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
    unsigned int out_len = 0;
    if (out == NULL || (data == NULL && len != 0)) {
        return -1;
    }
    if (data == NULL) {
        data = (const uint8_t *)"";
    }
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

int64_t pgpgen_search(const uint8_t *src, size_t len, size_t time_off,
                      uint32_t max_iter, unsigned leading, uint64_t *checked) {
    if (checked != NULL) {
        *checked = 0;
    }
    if (src == NULL || len < 4 || time_off > len - 4 || max_iter == 0 ||
        leading == 0 || leading > 8) {
        return -2;
    }

    uint8_t *buf = malloc(len);
    if (buf == NULL) {
        return -2;
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
        if (pgpgen_sha1(buf, len, hash) != 0) {
            free(buf);
            return -2;
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
