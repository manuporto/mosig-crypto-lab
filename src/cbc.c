#include "cbc.h"
#include "tczero.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>  /* strcpy */
#include "../res/uthash.h"

bool debug = false;
// Function to get random data and put it in the IV.
// Note getrandom function from linux/random.h was not used because we do not posses a new enough kernel (>= 3.17)
ssize_t generate_iv(uint64_t iv[]) {
    int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0) {
      // something went wrong
      return -1;
    } else {
      return read(randomData, iv, sizeof(uint64_t) * 2);
    }
}

size_t cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t plen) {
  uint64_t x[2] = {};
  uint64_t iv[2] = {};
  // First we generate the IV and we prepend it to the ciphertext
  generate_iv(iv);
  Uint64toUint8Arr(ct, iv[0], 0);
  Uint64toUint8Arr(ct, iv[1], 8);
  for (size_t i = 0; i * 8 < plen; i += 2) {
    x[0] = Uint8ArrtoUint64(pt, 8 * i);
    x[1] = Uint8ArrtoUint64(pt, 8 * (i + 1));

    x[0] ^= iv[0];
    x[1] ^= iv[1];


    tc0_encrypt(x, key);
    if(debug)
      printf("\nx after encryption: %lu %lu ", x[0], x[1]);

    // We need to offset the ciphertext by 16 bytes becaues of the IV
    Uint64toUint8Arr(ct, x[0], 8 * (i + 2));
    Uint64toUint8Arr(ct, x[1], 8 * (i + 3));

    iv[0] = x[0];
    iv[1] = x[1];
  }
  if(debug)
    printf("\n");
  return 0;
}

size_t cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t clen) {
  uint64_t x[2] = {};
  uint64_t iv[2] = {};
  uint64_t next_iv[2] = {};
  // We extract the IV prepended to the ciphertext
  iv[0] = Uint8ArrtoUint64(ct, 0);
  iv[1] = Uint8ArrtoUint64(ct, 8);
  for (size_t i = 0; i * 8 < clen; i += 2) {
    // We need to offset the ciphertext by 16 bytes becaues of the IV
    x[0] = Uint8ArrtoUint64(ct, 8 * (i + 2));
    x[1] = Uint8ArrtoUint64(ct, 8 * (i + 3));
    next_iv[0] = x[0];
    next_iv[1] = x[1];

    if(debug)
        printf("\nx before decryption: %lu %lu ", x[0], x[1]);

    tc0_decrypt(x, key);
    x[0] ^= iv[0];
    x[1] ^= iv[1];

    iv[0] = next_iv[0];
    iv[1] = next_iv[1];
        printf("\nx after decryption: %lu %lu ", x[0], x[1]);

    Uint64toUint8Arr(pt, x[0], 8 * i);
    Uint64toUint8Arr(pt, x[1], 8 * (i + 1));
  }
  return 0;
}

uint64_t Uint8ArrtoUint64(uint8_t *var, uint32_t lowest_pos) {
  return (((uint64_t)var[lowest_pos + 7]) << 56) |
  (((uint64_t)var[lowest_pos + 6]) << 48) |
  (((uint64_t)var[lowest_pos + 5]) << 40) |
  (((uint64_t)var[lowest_pos + 4]) << 32) |
  (((uint64_t)var[lowest_pos + 3]) << 24) |
  (((uint64_t)var[lowest_pos + 2]) << 16) |
  (((uint64_t)var[lowest_pos + 1]) << 8) |
  (((uint64_t)var[lowest_pos]) << 0);
}

void Uint64toUint8Arr(uint8_t *buf, uint64_t var, uint32_t lowest_pos) {
  buf[lowest_pos] = (var & 0x00000000000000FF) >> 0;
  buf[lowest_pos + 1] = (var & 0x000000000000FF00) >> 8;
  buf[lowest_pos + 2] = (var & 0x0000000000FF0000) >> 16;
  buf[lowest_pos + 3] = (var & 0x00000000FF000000) >> 24;
  buf[lowest_pos + 4] = (var & 0x000000FF00000000) >> 32;
  buf[lowest_pos + 5] = (var & 0x0000FF0000000000) >> 40;
  buf[lowest_pos + 6] = (var & 0x00FF000000000000) >> 48;
  buf[lowest_pos + 7] = (var & 0xFF00000000000000) >> 56;
}

void to_block(uint8_t *block, size_t block_size, uint8_t *ct, uint32_t offset){
  for (size_t i = 0; i < block_size; i++) {
    block[i] = ct[offset + i];
  }
}

struct uint8_t_hashable {
  char block_field[HALF_BLOCK_SIZE * 2];              /* key */
  UT_hash_handle hh;         /* makes this structure hashable */
};

uint64_t attack(uint8_t *ct, size_t ctlen){
  struct uint8_t_hashable *b, *tmp = NULL;
  struct uint8_t_hashable *hashtable = NULL;
  size_t block_size = HALF_BLOCK_SIZE * 2;
  uint64_t number_of_conflicts = 0;

  for (size_t i = 16; i < ctlen; i+=block_size) { //start from 16 to avoid IVs
    uint8_t block[block_size] = {0};
    to_block(block, block_size, ct, i);
    // printf("i %u\n",i);

    HASH_FIND_STR( hashtable, (char*) block, b);



    if( b==NULL ){
      b = (struct uint8_t_hashable *)malloc(sizeof *b);
      strcpy(b->block_field, (char*) block);
      HASH_ADD_STR( hashtable, block_field, b );
    }
    else{//TODO conflict
      printf("Conflict detected for block:\n");
      for (size_t i = 0; i < block_size; i++) {
          printf(" %u", (unsigned char) block[i]);
      }
      printf("\n");
      number_of_conflicts++;
    }
  }

  //printing function
  // for(b=hashtable; b != NULL; b=(struct uint8_t_hashable*)(b->hh.next)) {
  //   printf("\nblock");
  //   for (size_t i = 0; i < block_size; i++) {
  //     printf(" %u", (unsigned char) b->block_field[i]);
  //   }
  // }

  /* free the hash table contents */
  HASH_ITER(hh, hashtable, b, tmp) {
    HASH_DEL(hashtable, b);
    free(b);
  }

  return number_of_conflicts;
}
