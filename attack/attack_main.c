#include <stdio.h>
#include "../src/cbc.h"
#include "../src/tczero.h"


int main(int argc, char const *argv[]) {

 FILE *fp;

   fp = fopen("data.txt", "w+");
   bool verbose = false;

    uint64_t key[2] = {0, 0};
    size_t number_of_runs = 100;
    size_t number_of_plaintexts = 300;
    size_t plen;
    size_t clen;
    uint64_t number_of_runs_with_conflict;
    printf("--------- Running attack for the BLOCK_SIZE=%d %u times----------\n", HALF_BLOCK_SIZE*2, number_of_runs * number_of_plaintexts);
    for (size_t i = 0; i < number_of_plaintexts; i++) {
      plen = 10000;
      number_of_runs_with_conflict = 0;
      uint8_t plaintext[plen] = {0};
      // Cipher text has 16 additional bytes to store the IV
      clen = plen + 16;
      uint8_t ciphertext[clen] = {0};

      for (size_t j = 0; j < number_of_runs; j++) {//encrypt and attack
        cbc_enc(key, plaintext, ciphertext, plen);
        number_of_runs_with_conflict += attack(ciphertext, clen);
      }
      if(verbose){
          printf("=========== Number of conflicts: %lu for plaintext lenght %u\n",number_of_runs_with_conflict, plen);
          printf("===========> with these values we got a conflict with the probability of: %f \n", (float) number_of_runs_with_conflict / number_of_runs);
      }
      fprintf(fp, "%u, %f\n", plen, (float) number_of_runs_with_conflict / number_of_runs);
    }
    fclose(fp);
    return 0;
}
