#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <time.h>

#define likely(x) __builtin_expect((x), 1)
#define unlikely(x) __builtin_expect((x), 0)

uint16_t big2lil16(uint8_t in[sizeof(uint16_t)]) {
    return (in[0] << 8u) + in[1];
}

uint32_t big2lil32(uint8_t in[sizeof(uint32_t)]) {
    return (in[0] << 24u) + (in[1] << 16u) + (in[2] << 8u) + in[3];
}

void lil2big32(uint8_t out[sizeof(uint32_t)], uint32_t in) {
    out[3] = in & 0xffu;
    out[2] = (in >> 8u) & 0xffu;
    out[1] = (in >> 16u) & 0xffu;
    out[0] = (in >> 24u) & 0xffu;
}

inline int eor(uint8_t tmpp) {
    return (int)(((uint8_t)(tmpp << 4) ^ (uint8_t)(tmpp & 0xF0)) == 0);
}

int main(void) {

    uint8_t sm[3];
    int r;

    uint8_t* hashme = NULL;
    uint16_t hashme_size = 0;
    uint16_t offset = 0;
    uint32_t max_iter = 0;

    while(read(STDIN_FILENO, sm, 3) > 0) {
        char tag = sm[0];
        uint16_t len = big2lil16(&sm[1]);

        uint8_t* buf = NULL;
        buf = (uint8_t*) calloc(sizeof(uint8_t), len);

        if (!buf) goto dead;

        r = read(STDIN_FILENO, buf, len);
        if (r != len) goto dead;

        switch (tag) {
            case 0x01:
                hashme = calloc(1, len);
                if (!hashme) goto dead;
                memcpy(hashme, buf, len);
                hashme_size = len;
                break;
            case 0x02:
                if (len != sizeof(uint16_t)) goto dead;
                offset = big2lil16(buf);
                break;
            case 0x03:
                if (len != sizeof(uint32_t)) goto dead;
                max_iter = big2lil32(buf);
                break;
            default:
                goto dead;
        }
        free(buf);
    }

    if (!hashme) goto dead;
    if (!hashme_size) goto dead;
    if (!offset) goto dead;
    if (!max_iter) goto dead;

    int errnum;
    uint32_t unixtime = big2lil32(&hashme[offset]);
    uint32_t newtime = 0;
    int rc;

    uint8_t hash[20];

    for (uint32_t i = 0; i < max_iter; ++i) {
        newtime = unixtime - i;
        lil2big32(&hashme[offset], newtime);

        SHA1(hashme, hashme_size, hash);
        
        uint8_t currchar = 0x12;
        int ctr = 0;
        int contctr = 0;
        
        uint8_t tmpp;
        int numctr = 0;
        for (int i = 20-8; i < 20; ++i) {
            tmpp = hash[i];
            if (likely(!eor(tmpp))) {
                ctr = 0;
                contctr = 0;
                continue;
            }
            if (unlikely(tmpp == currchar)) {
                ++ctr;
                ++contctr;
            } else {
                ctr = 1;
                contctr = 1;
                currchar = tmpp;
            }
            if (unlikely(ctr >= 2)) {
                ++numctr;
                ctr = 0;
            }
            if (numctr >= 4 || (contctr >= 4 && numctr >= 3)) {
                printf("%d\n", newtime);
                return EXIT_SUCCESS;
            }
        }
        continue;
    }
dead:
    printf("-1\n");
    return EXIT_SUCCESS;
}
