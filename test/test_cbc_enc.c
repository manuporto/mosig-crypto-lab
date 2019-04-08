#include "../src/cbc.h"
#include "test_cbc_enc.h"

#include <stdio.h>

#define MAX_CIPHER_TEXT_SIZE 10
void test_cbc_enc_is_not_deterministic() {
    size_t plen = 8;
    uint8_t pt[] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t ct[MAX_CIPHER_TEXT_SIZE];
    uint64_t key[] = {0, 0};
    printf("Pringint plain text...\n");
    for (size_t i = 0; i < plen; i++) {
        printf("x%lu: %u\n", i, pt[i]);
    }
    printf("Done\n");
    cbc_enc(key, pt, ct, plen);
}

int main() {
    printf("-------------- Testing CBC encryption --------------\n");
    test_cbc_enc_is_not_deterministic();
    printf("-------------- Done testing CBC encryption --------------\n");
    return 0;
}