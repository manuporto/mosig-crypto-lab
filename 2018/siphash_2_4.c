#include <math.h>
#include <stdio.h>
#include <stdint.h>

#define C_SIP_ROUNDS 2
#define D_SIP_ROUNDS 4
#define B_BYTE_M 8

#define ROTATE_LEFT(x, b) (unsigned long)(((x) << (b)) | ((x) >> (64 - (b))))
// #define ROTATE_LEFT(x, b) (unsigned long)((x) << (b))

void sip_round(uint64_t *v0, uint64_t *v1, uint64_t *v2, uint64_t *v3, int rounds) {
    for (int i = 0; i < rounds; i++) {
        *v0 += *v1;
        *v2 += *v3;
        *v1 = ROTATE_LEFT(*v1, 13);
        *v3 = ROTATE_LEFT(*v3, 16);
        *v1 ^= *v0;
        *v3 ^= *v2;
        *v0 = ROTATE_LEFT(*v0, 32);
        *v2 += *v1;
        *v0 += *v3;
        *v1 = ROTATE_LEFT(*v1, 17);
        *v3 = ROTATE_LEFT(*v3, 21);
        *v1 ^= *v2;
        *v3 ^= *v0;
        *v2 = ROTATE_LEFT(*v2, 32); 
    }
}

uint64_t siphash_2_4(const uint64_t k[2], const uint8_t *m, const unsigned int mlen) {
    // Initialization
    uint64_t v0 = k[0] ^ 0x736f6d6570736575;
    uint64_t v1 = k[1] ^ 0x646f72616e646f6d;
    uint64_t v2 = k[0] ^ 0x6c7967656e657261;
    uint64_t v3 = k[1] ^ 0x7465646279746573;
    uint64_t ff = 0xff;

    printf("===================\n");
    printf("v0 = %#8lx\n", v0);
    printf("v1 = %#8lx\n", v1);
    printf("v2 = %#8lx\n", v2);
    printf("v3 = %#8lx\n\n", v3);

    // Compression
    for (unsigned int i = 0; i < mlen; i++) {
        v3 ^= m[i];
        sip_round(&v0, &v1, &v2, &v3, C_SIP_ROUNDS);
        v0 ^= m[i];
    }
    v2 ^= ff;

    sip_round(&v0, &v1, &v2, &v3, D_SIP_ROUNDS);

    uint64_t res = v0 ^ v1 ^ v2 ^ v3;
    printf("-------------------\n");
    printf("v0 = %#8lx\n", v0);
    printf("v1 = %#8lx\n", v1);
    printf("v2 = %#8lx\n", v2);
    printf("v3 = %#8lx\n\n", v3);

    return res;
}

int main() {
    uint64_t k[] = {0x0706050403020100, 0x0f0e0d0c0b0a0908};
    uint64_t k_2[] = {0, 0};
    uint8_t m[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};

    uint64_t res_1 = siphash_2_4(k, m, 8);
    uint64_t res_2 = siphash_2_4(k, NULL, 0);
    uint64_t res_3 = siphash_2_4(k_2, NULL, 0);

    printf("Res 1: %#8lx\n", res_1);
    printf("Res 2: %#8lx\n", res_2);
    printf("Res 3: %#8lx\n", res_3);
    return 0;
}