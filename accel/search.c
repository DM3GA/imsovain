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

int imsovain_sha1(const uint8_t *data, size_t len, uint8_t out[20]) {
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

/* Reuse one context for every hash in a scan. EVP_Digest() builds a context
   and takes OpenSSL 3's provider lock on each call, so threads stall on it.
   The context belongs to this scan. Worker threads do not share it.
*/
static EVP_MD_CTX *sha1_context(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return NULL;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int sha1_reuse(EVP_MD_CTX *ctx, const uint8_t *data, size_t len, uint8_t out[20]) {
    unsigned int out_len = 0;
    if (EVP_DigestInit_ex(ctx, NULL, NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
        return -1;
    }
    return out_len == 20 ? 0 : -1;
}

/* stop_on_match: return the unix time, or -1 when the window misses.
   Otherwise return 0 after hashing the whole window. -2 is a hard failure.
*/
static int64_t scan_times(const uint8_t *src, size_t len, size_t time_off,
                          uint32_t max_iter, const imsovain_filter *filter,
                          int stop_on_match, uint64_t *checked, uint64_t *matches) {
    if (checked != NULL) {
        *checked = 0;
    }
    if (matches != NULL) {
        *matches = 0;
    }
    if (src == NULL || len < 4 || time_off > len - 4 || max_iter == 0 || !imsovain_filter_ok(filter)) {
        return -2;
    }

    uint8_t *buf = malloc(len);
    EVP_MD_CTX *ctx = sha1_context();
    if (buf == NULL || ctx == NULL) {
        EVP_MD_CTX_free(ctx);
        free(buf);
        return -2;
    }
    memcpy(buf, src, len);

    uint32_t start = read_be32(buf + time_off);
    int64_t found = -1;
    uint64_t hits = 0;
    uint64_t room = (uint64_t)start + 1;
    uint32_t limit = max_iter;
    if ((uint64_t)limit > room) {
        limit = room > 0xffffffffu ? 0xffffffffu : (uint32_t)room;
    }

    uint64_t done = 0;
    for (uint32_t i = 0; i < limit; i++) {
        uint32_t stamp = start - i;
        write_be32(buf + time_off, stamp);
        uint8_t hash[20];
        if (sha1_reuse(ctx, buf, len, hash) != 0) {
            found = -2;
            break;
        }
        done++;
        if (imsovain_filter_match(hash, filter)) {
            hits++;
            if (stop_on_match) {
                found = (int64_t)stamp;
                break;
            }
        }
    }

    if (checked != NULL) {
        *checked = done;
    }
    if (matches != NULL) {
        *matches = hits;
    }
    EVP_MD_CTX_free(ctx);
    free(buf);
    if (found == -2 || stop_on_match) {
        return found;
    }
    return 0;
}

int64_t imsovain_search(const uint8_t *src, size_t len, size_t time_off,
                      uint32_t max_iter, const imsovain_filter *filter, uint64_t *checked) {
    return scan_times(src, len, time_off, max_iter, filter, 1, checked, NULL);
}

int imsovain_scan(const uint8_t *src, size_t len, size_t time_off, uint32_t max_iter,
                const imsovain_filter *filter, uint64_t *checked, uint64_t *matches) {
    int64_t rc = scan_times(src, len, time_off, max_iter, filter, 0, checked, matches);
    return rc == -2 ? -2 : 0;
}
