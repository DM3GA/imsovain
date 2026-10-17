#ifndef IMSOVAIN_SEARCH_H
#define IMSOVAIN_SEARCH_H

#include "filter.h"

#include <stddef.h>
#include <stdint.h>

/* SHA-1(data). Returns 0 on success. */
int imsovain_sha1(const uint8_t *data, size_t len, uint8_t out[20]);

/* Newest matching unix time in the backward scan, or -1 when none exists.
   Returns -2 when the request or the digest call fails.
   *checked is the number of digests computed. src is not modified.
   filter is prepared once and only read inside the loop.
*/
int64_t imsovain_search(const uint8_t *src, size_t len, size_t time_off,
                      uint32_t max_iter, const imsovain_filter *filter, uint64_t *checked);

/* Hash the whole window and count matches. Does not stop early.
   Returns 0, or -2 on failure. */
int imsovain_scan(const uint8_t *src, size_t len, size_t time_off, uint32_t max_iter,
                const imsovain_filter *filter, uint64_t *checked, uint64_t *matches);

#endif
