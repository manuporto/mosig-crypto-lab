#include "cbc.h"
#include "tczero.h"
#include <stdio.h>

size_t iv = 1;
size_t first_iv = 0;
size_t second_iv = 0;


size_t cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t plen) {
    uint64_t x[2] = {};
    for (size_t i = 0; i < 8; i++) {
        addToBitsAtPosition(i, &x[0], pt[i]);
        addToBitsAtPosition(i, &x[1], pt[i+8]);
    }

    x[0] ^= first_iv;
    x[1] ^= second_iv;
    printf("\nx before encryption: %lu %lu ", x[0], x[1]);
    tc0_encrypt(x, key);
    printf("\nx after encryption: %lu %lu ", x[0], x[1]);
    backToArray(ct, x[0], 0);
    backToArray(ct, x[1], 8);

    // ct[i] = x[0];
    // ct[(i + 1)]  = x[1];
    printf("\n");
    return 0;
}

size_t cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t clen) {
    uint64_t x[2] = {};
    for (size_t i = 0; i < 8; i++) {
      printf("%u %u\n", ct[i], ct[i+8]);
        addToBitsAtPosition(i, &x[0], ct[i]);
        addToBitsAtPosition(i, &x[1], ct[i+8]);
    }
    printf("\nx before decryption: %lu %lu ", x[0], x[1]);

    tc0_decrypt(x, key);
    x[0] ^= first_iv;
    x[1] ^= second_iv;

    printf("\nx after decryption: %lu %lu ", x[0], x[1]);

    uint8_t intermidiate[16] = {};
    backToArray(intermidiate, x[0], 0);
    backToArray(intermidiate, x[1], 8);

    for (size_t i = 0; i < 8; i++) {
      ct[7 - i] = intermidiate[i];
      ct[15 - i]= intermidiate[i+8];
    }



    // for (size_t i = 0; i < clen; i += 2) {
    //     uint64_t x[] = {ct[i], ct[(i + 1)]};
    //     uint64_t ci[] = {x[0], x[1]};
    //     tc0_decrypt(x, key);
    //     x[0] ^= first_iv;
    //     x[1] ^= second_iv;
    //     printf("++x[%u] %u, x[%u] %u \n",i, x[0], i+1, x[1]);
    //     first_iv = ci[0];
    //     second_iv = ci[1];
    //     pt[i] = x[0];
    //     pt[(i + 1)]  = x[1];
    // }
    // printf("\n");

    return 0;
}

void addToBitsAtPosition(uint8_t location, uint64_t *bits, uint8_t to_be_added)
{
    *bits |= ((uint64_t)to_be_added << (location * 8));
}

void backToArray(uint8_t *ct, uint64_t bits, size_t offset){
    for(uint_fast8_t i=0; i<8; i++)
    {
      ct[i + offset] = (bits >> (56-(i*8)) & 0xFF);
    }
}

int main(int argc, char const *argv[]) {
  uint64_t key[2] = {0,0};

  size_t plen = 16;
  // uint64_t plaintext[] = "0123456789abcdef";
  uint8_t plaintext[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

  uint8_t ciphertext[16] = {};
  uint8_t plaintext2[16] = {};

  cbc_enc(key, plaintext, ciphertext, plen);
  printf("encryption:\n");
  for (size_t i = 0; i < plen; i++) {
    printf("%u ", ciphertext[i]);
  }
  printf("\ndectyption:\n");
  first_iv = 0;
  second_iv = 0;
  cbc_dec(key, ciphertext, plaintext2, plen);
  for (size_t i = 0; i < plen; i++) {
    printf("%u ", plaintext2[i]);
  }
  return 0;
}
