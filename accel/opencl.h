#ifndef IMSOVAIN_OPENCL_H
#define IMSOVAIN_OPENCL_H

#include "filter.h"

#include <stddef.h>
#include <stdint.h>

/* Newest matching unix time in the backward scan, or -1 when none exists.
   Returns -2 when OpenCL or the request fails. *checked is how many hashes
   the GPU was given: the whole window, not an early exit.
   On failure, imsovain_opencl_last_error() is set on this thread.
   time_off must be 4. The preimage must fit in one SHA-1 block.
*/
int64_t imsovain_opencl_search(const uint8_t *src, size_t len, size_t time_off,
                             uint32_t max_iter, const imsovain_filter *filter,
                             uint64_t *checked);

/* NUL-terminated GPU name. Returns 0, or -1 when OpenCL cannot run. */
int imsovain_opencl_device(char *buf, size_t buflen);

const char *imsovain_opencl_last_error(void);

#endif
