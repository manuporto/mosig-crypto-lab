#include "../src/cbc.h"
#include "test_cbc.h"

#include <assert.h>
#include <stdbool.h> 
#include <stdio.h>

void test_cbc_enc_is_not_deterministic() {
    size_t plen = 8;
    uint8_t pt[8] = {0};
    // size_t plen = 32;
    // uint8_t pt[] = "0123456789abcdef0123456789abcdef";
    size_t clen = 24;
    // size_t clen = 48;
    uint8_t ct_1[24] = {0};
    uint8_t ct_2[24] = {0};
    uint8_t ct_3[24] = {0}; // If we remove this we get a stack smashed error, no idea why
    uint64_t key[2] = {0};
    printf("Pringint plain text...\n");
    for (size_t i = 0; i < plen; i++) {
        printf("x%lu: %u ", i, pt[i]);
    }
    printf("\nDone\n");
    cbc_enc(key, pt, ct_1, plen);
    cbc_enc(key, pt, ct_2, plen);

    printf("Printing cipher texts...\n");
    bool equals = true;
    for (size_t i = 0; i < clen; i++) {
        printf("%lu: %u | %u\n", i, ct_1[i], ct_2[i]);
        if (ct_1[i] != ct_2[i]) {
          equals = false;
          break;
        }
    }
    assert(!equals);
    printf("Done\n");
}

void test_cbc_enc_and_dec() {
uint64_t key[2] = {0, 0};
    //
    size_t plen = 32;
    uint8_t plaintext[] = "0123456789abcdef0123456789abcdef";
    // uint8_t plaintext[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    // Cipher text has 16 additional bytes to store the IV
    size_t clen = 48;
    uint8_t ciphertext[48] = {};
    uint8_t plaintext2[32] = {};

    cbc_enc(key, plaintext, ciphertext, plen);

    printf("Encryption (IV not included):\n");
    for (size_t i = 16; i < clen; i++) {
      printf("%u ", ciphertext[i]);
    }

    cbc_dec(key, ciphertext, plaintext2, plen);
    printf("\nDecryption:\n");
    for (size_t i = 0; i < plen; i++) {
      printf("%c", plaintext2[i]);
      assert(plaintext[i] == plaintext2[i]);
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