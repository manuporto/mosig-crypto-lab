#include "cbc.h"
#include "tczero.h"
#include <stdio.h>

uint64_t iv = 1;
uint64_t first_iv = 0;
uint64_t second_iv = 0;

size_t cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t plen) {
    uint64_t x[2] = {};
    for (size_t i = 0; i*8 < plen; i+=2) {
        x[0] = Uint8ArrtoUint64(pt, 8*i);
        x[1] = Uint8ArrtoUint64(pt, 8*(i+1));

        x[0] ^= first_iv;
        x[1] ^= second_iv;

        printf("\nx before encryption: %lu %lu ", x[0], x[1]);

        tc0_encrypt(x, key);

        printf("\nx after encryption: %lu %lu ", x[0], x[1]);

        Uint64toUint8Arr(ct, x[0], 8*i);
        Uint64toUint8Arr(ct, x[1], 8*(i+1));

        first_iv = x[0];
        second_iv = x[1];
    }
    printf("\n");
    return 0;
}

size_t cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t clen) {
    uint64_t x[2] = {};
    uint64_t next_iv[2] = {};
    for (size_t i = 0; i*8 < clen; i+=2) {
        x[0] = Uint8ArrtoUint64(ct, 8*i);
        x[1] = Uint8ArrtoUint64(ct, 8*(i+1));
        next_iv[0] = x[0];
        next_iv[1] = x[1];

        printf("\nx before decryption: %lu %lu ", x[0], x[1]);

        tc0_decrypt(x, key);
        x[0] ^= first_iv;
        x[1] ^= second_iv;

        first_iv = next_iv[0];
        second_iv = next_iv[1];
        printf("\nx after decryption: %lu %lu ", x[0], x[1]);

        Uint64toUint8Arr(pt, x[0], 8*i);
        Uint64toUint8Arr(pt, x[1], 8*(i+1));
    }
    return 0;
}

uint64_t Uint8ArrtoUint64 (uint8_t* var, uint32_t lowest_pos){
    return  (((uint64_t)var[lowest_pos+7]) << 56) |
            (((uint64_t)var[lowest_pos+6]) << 48) |
            (((uint64_t)var[lowest_pos+5]) << 40) |
            (((uint64_t)var[lowest_pos+4]) << 32) |
            (((uint64_t)var[lowest_pos+3]) << 24) |
            (((uint64_t)var[lowest_pos+2]) << 16) |
            (((uint64_t)var[lowest_pos+1]) << 8)  |
            (((uint64_t)var[lowest_pos])   << 0);
}

void Uint64toUint8Arr (uint8_t* buf, uint64_t var, uint32_t lowest_pos){
    buf[lowest_pos]     =   (var & 0x00000000000000FF) >> 0;
    buf[lowest_pos+1]   =   (var & 0x000000000000FF00) >> 8;
    buf[lowest_pos+2]   =   (var & 0x0000000000FF0000) >> 16;
    buf[lowest_pos+3]   =   (var & 0x00000000FF000000) >> 24;
    buf[lowest_pos+4]   =   (var & 0x000000FF00000000) >> 32;
    buf[lowest_pos+5]   =   (var & 0x0000FF0000000000) >> 40;
    buf[lowest_pos+6]   =   (var & 0x00FF000000000000) >> 48;
    buf[lowest_pos+7]   =   (var & 0xFF00000000000000) >> 56;
}
