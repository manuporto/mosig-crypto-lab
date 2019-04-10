#include "test_cbc_enc.h" 
#include <stdio.h>

int main() {
    printf("-------------- Running tests --------------\n");
    run_cbc_enc_tests();
    printf("-------------- Tests ran --------------\n");
    return 0;
}