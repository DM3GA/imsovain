#include "filter.h"

#include <string.h>

int imsovain_filter_parse(const uint8_t *blob, size_t len, imsovain_filter *out) {
    if (blob == NULL || out == NULL || len < 4) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    memset(out->head, 0xff, sizeof(out->head));
    memset(out->next, 0xff, sizeof(out->next));

    uint8_t kind = blob[0];
    uint8_t leading = blob[1];
    uint8_t count = blob[2];
    if (blob[3] != 0) {
        return -1;
    }
    if (kind == IMSOVAIN_FILTER_REPEAT) {
        if (leading < 1 || leading > 8 || count != 0 || len != 4) {
            return -1;
        }
        out->kind = kind;
        out->leading = leading;
        return 0;
    }
    if (kind != IMSOVAIN_FILTER_PREFIX || count < 1 || count > IMSOVAIN_FILTER_MAX) {
        return -1;
    }
    if (len != 4u + (size_t)count * 9u) {
        return -1;
    }

    const uint8_t *cursor = blob + 4;
    for (uint8_t i = 0; i < count; i++) {
        uint8_t prefix_len = cursor[0];
        if (prefix_len < 1 || prefix_len > 8) {
            return -1;
        }
        out->len[i] = prefix_len;
        memcpy(out->bytes[i], cursor + 1, 8);
        uint8_t first = out->bytes[i][0];
        out->next[i] = out->head[first];
        out->head[first] = i;
        cursor += 9;
    }
    out->kind = kind;
    out->count = count;
    return 0;
}

int imsovain_filter_match(const uint8_t hash[20], const imsovain_filter *filter) {
    if (hash == NULL || filter == NULL) {
        return 0;
    }
    const uint8_t *key_id = hash + 12;
    if (filter->kind == IMSOVAIN_FILTER_REPEAT) {
        uint8_t first = key_id[0];
        if ((first >> 4) != (first & 0x0f)) {
            return 0;
        }
        for (uint8_t i = 1; i < filter->leading; i++) {
            if (key_id[i] != first) {
                return 0;
            }
        }
        return 1;
    }
    if (filter->kind != IMSOVAIN_FILTER_PREFIX) {
        return 0;
    }

    /* The usual hash misses on this one load. memcmp runs only for a prefix
       that actually starts with this byte. */
    uint8_t index = filter->head[key_id[0]];
    while (index != 0xff) {
        uint8_t prefix_len = filter->len[index];
        const uint8_t *want = filter->bytes[index];
        uint8_t matched = 1;
        for (uint8_t i = 1; i < prefix_len; i++) {
            if (key_id[i] != want[i]) {
                matched = 0;
                break;
            }
        }
        if (matched) {
            return 1;
        }
        index = filter->next[index];
    }
    return 0;
}
