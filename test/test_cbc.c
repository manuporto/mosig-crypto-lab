#include "../src/cbc.h"
#include "test_cbc.h"

#include <stdio.h>

uint64_t first_iv = 0;
uint64_t second_iv = 0;

void test_cbc_enc_is_not_deterministic() {
    size_t plen = 8;
    uint8_t pt[] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t ct_1[plen];
    uint8_t ct_2[plen];
    uint64_t key[] = {0, 0};
    printf("Pringint plain text...\n");
    for (size_t i = 0; i < plen; i++) {
        printf("x%lu: %u\n", i, pt[i]);
    }
    printf("Done\n");
    cbc_enc(key, pt, ct_1, plen);
    cbc_enc(key, pt, ct_2, plen);

    printf("Printing cipher texts...\n");
    for (size_t i = 0; i < plen; i++) {
        printf("%lu: %u | %u\n", i, ct_1[i], ct_2[i]);
    }
    printf("Done\n");
}

void test_cbc_enc_and_dec() {
  uint64_t key[2] = {0, 0};
  size_t plen = 32;
  uint8_t plaintext[32] = "0123456789abcdef0123456789abcdef";
  uint8_t ciphertext[32] = {};
  uint8_t plaintext2[32] = {};

  cbc_enc(key, plaintext, ciphertext, plen);

  printf("Encryption:\n");
  for (size_t i = 0; i < plen; i++) {
    printf("%u ", ciphertext[i]);
  }
  first_iv = 0;
  second_iv = 0;
  cbc_dec(key, ciphertext, plaintext2, plen);
  printf("\nDecryption:\n");
  for (size_t i = 0; i < plen; i++) {
    printf("%c", plaintext2[i]);
  }
}

void run_cbc_enc_tests() {
    printf("-------------- Testing CBC encryption determinism --------------\n");
    test_cbc_enc_is_not_deterministic();
    printf("-------------- Done testing CBC encryption determinism --------------\n");

    printf("-------------- Testing CBC encryption and decryption --------------\n");
    test_cbc_enc_and_dec();
    printf("-------------- Done testing CBC encryption and decryption --------------\n");
}