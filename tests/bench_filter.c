/* Time the byte-prefix filter against POSIX regex.
   The production scan does not call regexec. This file exists so the check
   can measure that choice on the same hashes.

   Usage: bench_filter PREIMAGE REPEAT_BLOB WORD_BLOB RUN_BLOB ONE_BLOB ITERS
   Prints: kind name count seconds rate hits
*/
#include "filter.h"
#include "search.h"

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void die(const char *message) {
    fprintf(stderr, "bench_filter: %s\n", message);
    exit(1);
}

static double now_seconds(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        die("clock_gettime failed");
    }
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static uint8_t *load_file(const char *path, size_t *length) {
    FILE *handle = fopen(path, "rb");
    if (handle == NULL) {
        die("could not open an input file");
    }
    if (fseek(handle, 0, SEEK_END) != 0) {
        die("could not seek an input file");
    }
    long size = ftell(handle);
    if (size < 0) {
        die("could not size an input file");
    }
    if (fseek(handle, 0, SEEK_SET) != 0) {
        die("could not rewind an input file");
    }
    uint8_t *buf = malloc(size == 0 ? 1 : (size_t)size);
    if (buf == NULL) {
        die("out of memory");
    }
    if (size > 0 && fread(buf, 1, (size_t)size, handle) != (size_t)size) {
        die("short read");
    }
    fclose(handle);
    *length = (size_t)size;
    return buf;
}

static pgpgen_filter load_filter(const char *path) {
    size_t length = 0;
    uint8_t *blob = load_file(path, &length);
    pgpgen_filter filter;
    if (pgpgen_filter_parse(blob, length, &filter) != 0) {
        die("filter blob is not valid");
    }
    free(blob);
    return filter;
}

static uint64_t xorshift(uint64_t *state) {
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

static void fill_hash(uint8_t hash[20], uint64_t *state) {
    uint64_t first = xorshift(state);
    uint64_t second = xorshift(state);
    uint32_t tail = (uint32_t)xorshift(state);
    memcpy(hash, &first, 8);
    memcpy(hash + 8, &second, 8);
    memcpy(hash + 16, &tail, 4);
}

static char hex_digit(unsigned value) {
    return (char)(value < 10 ? '0' + value : 'A' + (value - 10));
}

static void key_id_hex(const uint8_t hash[20], char out[17]) {
    const uint8_t *key_id = hash + 12;
    for (int i = 0; i < 8; i++) {
        out[i * 2] = hex_digit(key_id[i] >> 4);
        out[i * 2 + 1] = hex_digit(key_id[i] & 0x0f);
    }
    out[16] = '\0';
}

static void compile_regex(const pgpgen_filter *filter, regex_t *compiled, int first_only) {
    if (filter->kind != PGPGEN_FILTER_PREFIX || filter->count < 1) {
        die("regex bench needs a prefix filter");
    }
    uint8_t count = first_only ? 1 : filter->count;
    size_t cap = 8;
    for (uint8_t i = 0; i < count; i++) {
        cap += (size_t)filter->len[i] * 2u + 1u;
    }
    char *pattern = malloc(cap);
    if (pattern == NULL) {
        die("out of memory");
    }
    size_t used = 0;
    pattern[used++] = '^';
    pattern[used++] = '(';
    for (uint8_t i = 0; i < count; i++) {
        if (i != 0) {
            pattern[used++] = '|';
        }
        for (uint8_t j = 0; j < filter->len[i]; j++) {
            pattern[used++] = hex_digit(filter->bytes[i][j] >> 4);
            pattern[used++] = hex_digit(filter->bytes[i][j] & 0x0f);
        }
    }
    pattern[used++] = ')';
    pattern[used] = '\0';
    int rc = regcomp(compiled, pattern, REG_EXTENDED | REG_NOSUB);
    if (rc != 0) {
        char err[256];
        regerror(rc, compiled, err, sizeof err);
        fprintf(stderr, "bench_filter: regcomp %s: %s\n", pattern, err);
        exit(1);
    }
    free(pattern);
}

static uint32_t clamp_limit(const uint8_t *preimage, size_t len, uint32_t iters) {
    if (preimage == NULL || len < 8) {
        die("preimage is too short");
    }
    uint32_t start = ((uint32_t)preimage[4] << 24) | ((uint32_t)preimage[5] << 16) |
                     ((uint32_t)preimage[6] << 8) | (uint32_t)preimage[7];
    uint64_t room = (uint64_t)start + 1;
    if ((uint64_t)iters > room) {
        die("iteration count does not fit in the creation-time window");
    }
    return iters;
}

static void regex_scan(const uint8_t *src, size_t len, uint32_t iters, const regex_t *compiled,
                       uint64_t *checked, uint64_t *hits) {
    uint8_t *buf = malloc(len);
    if (buf == NULL) {
        die("out of memory");
    }
    memcpy(buf, src, len);
    uint32_t start = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
                     ((uint32_t)buf[6] << 8) | (uint32_t)buf[7];
    uint64_t found = 0;
    for (uint32_t i = 0; i < iters; i++) {
        uint32_t stamp = start - i;
        buf[4] = (uint8_t)(stamp >> 24);
        buf[5] = (uint8_t)(stamp >> 16);
        buf[6] = (uint8_t)(stamp >> 8);
        buf[7] = (uint8_t)stamp;
        uint8_t hash[20];
        if (pgpgen_sha1(buf, len, hash) != 0) {
            die("SHA-1 failed");
        }
        char hex[17];
        key_id_hex(hash, hex);
        int rc = regexec(compiled, hex, 0, NULL, 0);
        if (rc == 0) {
            found++;
        } else if (rc != REG_NOMATCH) {
            die("regexec failed");
        }
    }
    free(buf);
    *checked = iters;
    *hits = found;
}

static uint64_t bench_recompile(const pgpgen_filter *filter, uint32_t iters, uint64_t seed) {
    uint64_t state = seed;
    uint64_t hits = 0;
    for (uint32_t n = 0; n < iters; n++) {
        uint8_t hash[20];
        fill_hash(hash, &state);
        char hex[17];
        key_id_hex(hash, hex);
        regex_t compiled;
        compile_regex(filter, &compiled, 0);
        int rc = regexec(&compiled, hex, 0, NULL, 0);
        regfree(&compiled);
        if (rc == 0) {
            hits++;
        } else if (rc != REG_NOMATCH) {
            die("regexec failed");
        }
    }
    return hits;
}

static uint64_t bench_match(const pgpgen_filter *filter, const regex_t *compiled, int use_regex,
                            uint32_t iters, uint64_t seed) {
    uint64_t state = seed;
    uint64_t hits = 0;
    for (uint32_t n = 0; n < iters; n++) {
        uint8_t hash[20];
        fill_hash(hash, &state);
        if (use_regex) {
            char hex[17];
            key_id_hex(hash, hex);
            int rc = regexec(compiled, hex, 0, NULL, 0);
            if (rc == 0) {
                hits++;
            } else if (rc != REG_NOMATCH) {
                die("regexec failed");
            }
        } else if (pgpgen_filter_match(hash, filter)) {
            hits++;
        }
    }
    return hits;
}

static void expect_byte(const pgpgen_filter *filter, const uint8_t key[8], int want) {
    uint8_t hash[20];
    memset(hash, 0x5a, sizeof hash);
    memcpy(hash + 12, key, 8);
    if (pgpgen_filter_match(hash, filter) != want) {
        die("byte filter self-check failed");
    }
}

static void expect_match(const pgpgen_filter *filter, const regex_t *compiled, const uint8_t key[8],
                         int want) {
    uint8_t hash[20];
    memset(hash, 0x5a, sizeof hash);
    memcpy(hash + 12, key, 8);
    char hex[17];
    key_id_hex(hash, hex);
    int byte_hit = pgpgen_filter_match(hash, filter);
    int regex_hit = regexec(compiled, hex, 0, NULL, 0) == 0;
    if (byte_hit != want || regex_hit != want) {
        fprintf(stderr, "bench_filter: self-check failed for %s byte=%d regex=%d want=%d\n", hex,
                byte_hit, regex_hit, want);
        exit(1);
    }
}

static void report(const char *kind, const char *name, uint64_t count, double seconds, uint64_t hits) {
    double rate = seconds > 0.0 ? (double)count / seconds : 0.0;
    printf("%s %s %llu %.9f %.3f %llu\n", kind, name, (unsigned long long)count, seconds, rate,
           (unsigned long long)hits);
}

static void time_byte_scan(const char *name, const uint8_t *preimage, size_t len,
                           const pgpgen_filter *filter, uint32_t iters) {
    uint64_t checked = 0;
    uint64_t hits = 0;
    double start = now_seconds();
    int rc = pgpgen_scan(preimage, len, 4, iters, filter, &checked, &hits);
    double elapsed = now_seconds() - start;
    if (rc != 0 || checked != iters) {
        die("byte scan did not finish the requested window");
    }
    report("byte_scan", name, checked, elapsed, hits);
}

int main(int argc, char **argv) {
    if (argc != 7) {
        die("usage: bench_filter PREIMAGE REPEAT WORD RUN ONE ITERS");
    }
    uint32_t iters = (uint32_t)strtoul(argv[6], NULL, 10);
    if (iters < 1000) {
        die("iteration count is too small");
    }
    size_t len = 0;
    uint8_t *preimage = load_file(argv[1], &len);
    if (len < 8) {
        die("preimage is too short");
    }
    clamp_limit(preimage, len, iters);
    pgpgen_filter repeat_filter = load_filter(argv[2]);
    pgpgen_filter word_filter = load_filter(argv[3]);
    pgpgen_filter run_filter = load_filter(argv[4]);
    pgpgen_filter one_filter = load_filter(argv[5]);

    regex_t word_re;
    regex_t one_re;
    compile_regex(&word_filter, &word_re, 0);
    compile_regex(&one_filter, &one_re, 1);

    uint8_t deadbeef[8] = {0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44};
    uint8_t deadc0de[8] = {0xde, 0xad, 0xc0, 0xde, 0x00, 0x00, 0x00, 0x00};
    uint8_t deadmiss[8] = {0xde, 0xad, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t run_hit[8] = {0x00, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd};
    uint8_t run_miss[8] = {0x00, 0x11, 0x22, 0x34, 0x00, 0x00, 0x00, 0x00};
    uint8_t code_only[8] = {0xc0, 0xde, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    expect_match(&word_filter, &word_re, deadbeef, 1);
    expect_match(&word_filter, &word_re, deadc0de, 1);
    expect_match(&word_filter, &word_re, deadmiss, 0);
    expect_match(&word_filter, &word_re, code_only, 0);
    expect_match(&one_filter, &one_re, deadbeef, 1);
    expect_match(&one_filter, &one_re, deadc0de, 0);
    expect_byte(&run_filter, run_hit, 1);
    expect_byte(&run_filter, run_miss, 0);
    uint8_t repeated[8];
    memset(repeated, 0xff, sizeof repeated);
    expect_byte(&repeat_filter, repeated, 1);
    repeated[0] = 0x12;
    expect_byte(&repeat_filter, repeated, 0);

    const uint64_t seed = 0x6a09e667f3bcc909ull;
    double start = now_seconds();
    uint64_t byte_word_hits = bench_match(&word_filter, &word_re, 0, iters, seed);
    report("byte_match", "word", iters, now_seconds() - start, byte_word_hits);

    start = now_seconds();
    uint64_t regex_word_hits = bench_match(&word_filter, &word_re, 1, iters, seed);
    report("regex_match", "word", iters, now_seconds() - start, regex_word_hits);

    start = now_seconds();
    uint64_t byte_one_hits = bench_match(&one_filter, &one_re, 0, iters, seed);
    report("byte_match", "one", iters, now_seconds() - start, byte_one_hits);

    start = now_seconds();
    uint64_t regex_one_hits = bench_match(&one_filter, &one_re, 1, iters, seed);
    report("regex_match", "one", iters, now_seconds() - start, regex_one_hits);

    if (byte_word_hits != regex_word_hits || byte_one_hits != regex_one_hits) {
        die("byte filter and regex disagreed on the random sample");
    }

    /* Rebuilding the regex on every hash is the slow path people hit when the
       pattern is compiled inside the scan. Keep this sample smaller. */
    uint32_t recompile_iters = iters > 20000u ? 20000u : iters;
    start = now_seconds();
    uint64_t recompile_hits = bench_recompile(&word_filter, recompile_iters, seed);
    report("regex_recompile", "word", recompile_iters, now_seconds() - start, recompile_hits);

    time_byte_scan("repeat", preimage, len, &repeat_filter, iters);
    time_byte_scan("word", preimage, len, &word_filter, iters);
    time_byte_scan("run", preimage, len, &run_filter, iters);
    time_byte_scan("one", preimage, len, &one_filter, iters);

    uint64_t checked = 0;
    uint64_t hits = 0;
    start = now_seconds();
    regex_scan(preimage, len, iters, &word_re, &checked, &hits);
    report("regex_scan", "word", checked, now_seconds() - start, hits);

    checked = 0;
    hits = 0;
    start = now_seconds();
    regex_scan(preimage, len, iters, &one_re, &checked, &hits);
    report("regex_scan", "one", checked, now_seconds() - start, hits);

    regfree(&word_re);
    regfree(&one_re);
    free(preimage);
    return 0;
}
