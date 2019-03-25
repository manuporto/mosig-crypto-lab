#include <math.h>
#include <stdio.h>
#include <stdint.h>

#define C_SIP_ROUNDS 2
#define D_SIP_ROUNDS 4
#define B_BYTE_M 8


uint64_t siphash_2_4(uint64_t k[2], uint8_t *m, unsigned int mlen) {
    // Initialization
    uint64_t v0 = k[0] ^ 0x736f6d6570736575;
    uint64_t v1 = k[1] ^ 0x646f72616e646f6d;
    uint64_t v2 = k[0] ^ 0x6c7967656e657261;
    uint64_t v3 = k[1] ^ 0x7465646279746573;
    uint64_t ff = 0xff;

    printf("v0 = %#8lx\n", v0);
    printf("v1 = %#8lx\n", v1);
    printf("v2 = %#8lx\n", v2);
    printf("v3 = %#8lx\n", v3);

    // Compression
    for (unsigned int i = 0; i < mlen; i++) {
        printf("Mi = %#x\n", m[i]);
        v3 ^= m[i];
        for (unsigned int j = 0; j < C_SIP_ROUNDS; j++) v0 ^= m[i];
    }

    // for (unsigned int i = 0; i < D_SIP_ROUNDS; i++) v2 ^= ff;

    uint64_t res = v0;
    res ^= v1; 
    res ^= v2; 
    res ^= v3;
    printf("Res: %#8lx\n", res);
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