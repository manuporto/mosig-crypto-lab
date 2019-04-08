#include "cbc.h"
#include "tczero.h"

size_t cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t plen) {
    size_t iv = 1;
    uint64_t first_iv = 1;
    uint64_t second_iv = 1;
    for (size_t i = 0; i < ((plen % HALF_BLOCK_SIZE) - 1); i++) {
        uint64_t x[] = {pt[HALF_BLOCK_SIZE * i], pt[HALF_BLOCK_SIZE * (i + 1)]};
        x[0] ^= first_iv;
        x[1] ^= second_iv;
        tc0_encrypt(x, key);
        first_iv = x[0];
        second_iv = x[1];
        ct[HALF_BLOCK_SIZE * i] = x[0];
        ct[HALF_BLOCK_SIZE * (i + 1)]  = x[1];
    }
    return 0;
}

size_t cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t clen) {
    size_t iv = 1;
    uint64_t first_iv = 1;
    uint64_t second_iv = 1;
    for (size_t i = 0; i < ((clen % HALF_BLOCK_SIZE) - 1); i++) {
        uint64_t x[] = {ct[HALF_BLOCK_SIZE * i], ct[HALF_BLOCK_SIZE * (i + 1)]};
        uint64_t ci[] = {x[0], x[1]};
        tc0_decrypt(x, key);
        x[0] ^= first_iv;
        x[1] ^= second_iv;
        first_iv = ci[0];
        second_iv = ci[1];
        pt[HALF_BLOCK_SIZE * i] = x[0];
        pt[HALF_BLOCK_SIZE * (i + 1)]  = x[1];
    }
    return 0;
}
