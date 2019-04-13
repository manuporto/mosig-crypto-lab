#include "test_cbc.h" 
#include <stdio.h>

int main(int argc, char const *argv[]) {
    printf("-------------- Running tests --------------\n");
    run_cbc_enc_tests();
    printf("-------------- Tests ran --------------\n");
    return 0;
}