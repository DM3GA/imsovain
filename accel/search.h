#ifndef PGPGEN_SEARCH_H
#define PGPGEN_SEARCH_H

#include <stddef.h>
#include <stdint.h>

/* SHA-1(data). Returns 0 on success. */
int pgpgen_sha1(const uint8_t *data, size_t len, uint8_t out[20]);

/* Newest matching unix time in the backward scan, or -1 when none exists.
   Returns -2 when the request or the digest call fails.
   *checked is the number of digests computed. src is not modified.
*/
int64_t pgpgen_search(const uint8_t *src, size_t len, size_t time_off,
                      uint32_t max_iter, unsigned leading, uint64_t *checked);

#endif
