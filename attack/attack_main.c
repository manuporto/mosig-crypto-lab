#include <stdio.h>
#include <math.h>
#include "../src/cbc.h"
#include "../src/tczero.h"


int main(int argc, char const *argv[]) {
    // FILE *fp;
    // fp = fopen("data.txt", "w+");

    bool verbose = true;
    uint64_t key[2] = {0, 0};
    size_t number_of_runs = 100;
    size_t number_of_plaintexts = 1;
    size_t plen = pow(2, HALF_BLOCK_SIZE) * ( (HALF_BLOCK_SIZE) * 2); // number of blocks * number of bits in a block
    size_t clen;
    uint64_t number_of_runs_with_conflict;
    printf("--------- Running attack for the BLOCK_SIZE=%d %u times----------\n", HALF_BLOCK_SIZE*2, number_of_runs * number_of_plaintexts);
    for (size_t i = 0; i < number_of_plaintexts; i++) {
      number_of_runs_with_conflict = 0;
      uint8_t * plaintext = (uint8_t*) malloc(plen* sizeof(uint8_t));
      for (size_t i = 0; i < plen; i++) {
        plaintext[i] = i%255;
      }
      // Cipher text has 16 additional bytes to store the IV
      clen = plen + 16;
      uint8_t * ciphertext = (uint8_t*) calloc(clen, sizeof(uint8_t));
      printf("%d\n", i);
      for (size_t j = 0; j < number_of_runs; j++) {//encrypt and attack
        cbc_enc(key, plaintext, ciphertext, plen);
        printf("encrypted\n");
        number_of_runs_with_conflict += attack(ciphertext, clen);
        printf("number_of_runs_with_conflict: %d\n", number_of_runs_with_conflict);
      }
      if(verbose){
          printf("=========== Number of conflicts: %lu for plaintext lenght %u = %f blocks\n",number_of_runs_with_conflict, plen, (float) plen / (HALF_BLOCK_SIZE * 2));
          printf("===========> with these values we got a conflict with the probability of: %f \n", (float) number_of_runs_with_conflict / number_of_runs);
      }
      // fprintf(fp, "%f\n", (float) number_of_runs_with_conflict / number_of_runs);
    }
    // fclose(fp);
    return 0;
}
