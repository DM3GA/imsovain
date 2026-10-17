#ifndef PGPGEN_FILTER_H
#define PGPGEN_FILTER_H

#include <stddef.h>
#include <stdint.h>

/* Key-id filters are byte prefixes, not regular expressions.
   A repeat filter wants `leading` identical doubled-nibble bytes.
   A prefix filter wants any one of `count` exact prefixes.
   The packed blob is:
     kind, leading, count, 0
     then `count` records of: length, 8 bytes (length is 1..8)
   kind 0 is repeat (count must be 0 and the blob is exactly 4 bytes).
   kind 1 is prefixes.
*/
#define PGPGEN_FILTER_REPEAT 0u
#define PGPGEN_FILTER_PREFIX 1u
#define PGPGEN_FILTER_MAX 32u

typedef struct pgpgen_filter {
    uint8_t kind;
    uint8_t leading;
    uint8_t count;
    uint8_t len[PGPGEN_FILTER_MAX];
    uint8_t bytes[PGPGEN_FILTER_MAX][8];
    uint8_t head[256];
    uint8_t next[PGPGEN_FILTER_MAX];
} pgpgen_filter;

/* 0 when the blob is a filter this scanner can run. */
int pgpgen_filter_parse(const uint8_t *blob, size_t len, pgpgen_filter *out);

/* 1 when the last eight bytes of a SHA-1 fingerprint match. */
int pgpgen_filter_match(const uint8_t hash[20], const pgpgen_filter *filter);

#endif
