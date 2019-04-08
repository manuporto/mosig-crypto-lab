#include "cbc.h"
#include "tczero.h"
#include <stdio.h>

size_t iv = 1;
uint64_t first_iv = 1;
uint64_t second_iv = 1;


size_t cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t plen) {
    for (size_t i = 0; i < plen; i += 2) {
        uint64_t x[] = {pt[i], pt[(i + 1)]};
        printf("%c%c", x[0], x[1]);
        x[0] ^= first_iv;
        x[1] ^= second_iv;
        tc0_encrypt(x, key);
        first_iv = x[0];
        second_iv = x[1];
        ct[i] = x[0];
        ct[(i + 1)]  = x[1];
    }
    printf("\n");
    return 0;
}

size_t cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t clen) {
    for (size_t i = 0; i < clen; i += 2) {
        uint64_t x[] = {ct[i], ct[(i + 1)]};
        uint64_t ci[] = {x[0], x[1]};
        tc0_decrypt(x, key);
        x[0] ^= first_iv;
        x[1] ^= second_iv;
        printf("++ %u %u \n",x[0], x[1]);
        first_iv = ci[0];
        second_iv = ci[1];
        pt[i] = x[0];
        pt[(i + 1)]  = x[1];
    }
    printf("\n");

    return 0;
}

int main(int argc, char const *argv[]) {
  uint64_t key[2] = {0,0};

  size_t plen = 16;
  uint8_t plaintext[] = "0123456789abcdef";
  uint8_t ciphertext[plen];
  uint8_t plaintext2[plen];

  cbc_enc(key, plaintext, ciphertext, plen);
  for (size_t i = 0; i < plen; i++) {
    printf("%u ", ciphertext[i]);
  }
  printf("\n");
  cbc_dec(key, ciphertext, plaintext2, plen);
  for (size_t i = 0; i < plen; i++) {
    printf("%c ", plaintext2[i]);
  }
  return 0;
}
