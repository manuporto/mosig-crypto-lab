#include "cbc.h"
#include "tczero.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>  /* strcpy */
#include "../res/uthash.h"
#include "functional"
#include <set>
#include <vector>

bool debug = true;
bool show_conflicts = true;
bool num_collision_mode = false;

//struct for collision attack using uthash
struct block_hashable {
  char block_field[HALF_BLOCK_SIZE * 2];
  size_t index;              /* key */
  UT_hash_handle hh;         /* makes this structure hashable */
};



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
  Uint64toUint8Arr(ct, iv[0], 0, 8);
  Uint64toUint8Arr(ct, iv[1], 8, 8);
  for (size_t i = 0; i * (HALF_BLOCK_SIZE/8) < plen; i += 2) {
    x[0] = Uint8ArrtoUint64(pt, (HALF_BLOCK_SIZE/8) * i, HALF_BLOCK_SIZE/8);
    x[1] = Uint8ArrtoUint64(pt, (HALF_BLOCK_SIZE/8) * (i + 1), HALF_BLOCK_SIZE/8);

    x[0] ^= iv[0];
    x[1] ^= iv[1];

    if(debug)
      printf("\nx before encryption: %lu %lu ", x[0], x[1]);
    tc0_encrypt(x, key);
    if(debug)
      printf("\nx after encryption: %lu %lu ", x[0], x[1]);

    // We need to offset the ciphertext by 16 bytes becaues of the IV
    Uint64toUint8Arr(ct, x[0], 16 + (HALF_BLOCK_SIZE/8) * (i), HALF_BLOCK_SIZE/8);
    Uint64toUint8Arr(ct, x[1], 16 + (HALF_BLOCK_SIZE/8) * (i + 1), HALF_BLOCK_SIZE/8);

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
  iv[0] = Uint8ArrtoUint64(ct, 0, 8);
  iv[1] = Uint8ArrtoUint64(ct, 8, 8);
  for (size_t i = 16; i < clen; i += 2 *  (HALF_BLOCK_SIZE/8)) {
    // We need to offset the ciphertext by 16 bytes becaues of the IV
    x[0] = Uint8ArrtoUint64(ct, i, HALF_BLOCK_SIZE/8);
    x[1] = Uint8ArrtoUint64(ct, (i + HALF_BLOCK_SIZE/8), HALF_BLOCK_SIZE/8);
    next_iv[0] = x[0];
    next_iv[1] = x[1];

    if(debug)
        printf("\nx before decryption: %lu %lu ", x[0], x[1]);

    tc0_decrypt(x, key);
    x[0] ^= iv[0];
    x[1] ^= iv[1];

    iv[0] = next_iv[0];
    iv[1] = next_iv[1];
    // if (debug)
    //   printf("\nx after decryption: %lu %lu ", x[0], x[1]);

    Uint64toUint8Arr(pt, x[0], (i - 16), (HALF_BLOCK_SIZE/8));
    Uint64toUint8Arr(pt, x[1], (i - 16 + HALF_BLOCK_SIZE/8), (HALF_BLOCK_SIZE/8));
  }
  return 0;
}

uint64_t Uint8ArrtoUint64(uint8_t *var, uint32_t lowest_pos, size_t number_of_chars) {
  uint8_t inv_var[number_of_chars];
  size_t j = (number_of_chars + lowest_pos - 1);
  for (size_t i = 0; i < number_of_chars; i++) {
    inv_var[i] = var[j];
    j--;
  }
  uint64_t x = 0;
  for (size_t i = 0; i < number_of_chars; i++) {
    x |= inv_var[i];
    if (i != (number_of_chars -1)) x <<= 8;
  }
  return x;
}

void Uint64toUint8Arr(uint8_t *buf, uint64_t var, uint32_t lowest_pos, size_t number_of_chars) {
  uint64_t mask = 0x00000000000000FF;
  for (size_t i = 0; i < number_of_chars; i++) {
    buf[lowest_pos + i] = (var & mask) >> (i * 8);
    mask <<= 8;
  }
  // buf[lowest_pos] = (var & 0x00000000000000FF) >> 0;
  // buf[lowest_pos + 1] = (var & 0x000000000000FF00) >> 8;
  // buf[lowest_pos + 2] = (var & 0x0000000000FF0000) >> 16;
  // buf[lowest_pos + 3] = (var & 0x00000000FF000000) >> 24;
  // buf[lowest_pos + 4] = (var & 0x000000FF00000000) >> 32;
  // buf[lowest_pos + 5] = (var & 0x0000FF0000000000) >> 40;
  // buf[lowest_pos + 6] = (var & 0x00FF000000000000) >> 48;
  // buf[lowest_pos + 7] = (var & 0xFF00000000000000) >> 56;
}

void to_block(uint8_t *block, size_t block_size, uint8_t *ct, uint32_t offset){
  for (size_t i = 0; i < block_size; i++) {
    block[i] = ct[offset + i];
  }
}

void xor_block(uint8_t *ct1, uint8_t *ct2, uint8_t *value, size_t block_size){
  for (size_t i = 0; i < block_size; i++) {
    value[i] = ct1[i] ^ ct2[i];
  }
}

void fill_vector(std::vector<uint8_t> &v, uint8_t* data, size_t block_size, uint32_t offset){
  v.erase(v.begin(), v.end());
  for (size_t i = 0; i < block_size; i++) {
    v.push_back(data[i + offset]);
  }
}

uint64_t attack(uint8_t *ct, size_t ctlen){
  std::set<std::vector<uint8_t>> hashset;



  size_t block_size = HALF_BLOCK_SIZE * 2;
  uint64_t number_of_conflicts = 0;
  std::vector<uint8_t> vec;
  uint8_t xored_value[block_size] = {0};
  for (size_t i = 16; i < ctlen; i+=block_size) { //start from 16 to avoid IVs
    fill_vector(vec, ct, block_size, i);

    auto conflict = hashset.find(vec);
    if( conflict == hashset.end()){
      hashset.insert(vec);
    }
    else{
      if(show_conflicts){//set to true if want to display conflicting blocks and their XOR
        const std::vector<uint8_t>& vec_2 = (*conflict);
          printf("%u, %u\n", vec.size(), vec_2.size());
          for (size_t j = 0; j < block_size; j++) {
              printf("%u %u | ", vec[j], vec_2[j]);
          }
          // printf("\n");
      }
      number_of_conflicts++;
      if(num_collision_mode == false)//
        break;
    }
  }
  printf("%u\n", hashset.size());
  // struct block_hashable *b, *tmp = NULL;
  // struct block_hashable *hashtable = NULL;
  // size_t block_size = HALF_BLOCK_SIZE * 2;
  // uint64_t number_of_conflicts = 0;
  // uint8_t xored_value[block_size] = {0};
  //
  // for (size_t i = 16; i < ctlen; i+=block_size) { //start from 16 to avoid IVs
  //   uint8_t block[block_size] = {0};
  //   to_block(block, block_size, ct, i);
  //   HASH_FIND_STR( hashtable, (char*) block, b);
  //   if( b==NULL ){
  //     b = (struct block_hashable *)malloc(sizeof *b);
  //     strcpy(b->block_field, (char*) block);
  //     b->index = i;
  //     HASH_ADD_STR( hashtable, block_field, b );
  //   }
  //   else{
  //     if(show_conflicts){//set to true if want to display conflicting blocks and their XOR
  //         // xor_block( block, (uint8_t*) b->block_field, xored_value, block_size);
  //         // printf("Conflict detected between elementes on index: %u and %u \n", i, b->index);
  //         // printf("m_%d xor m_%d = c_%d xor c_%d = ", i, b->index, i-1, b->index-1);
  //         for (size_t j = 0; j < block_size; j++) {
  //             // printf(" %u", xored_value[j]);
  //             printf("%u %u | ", (char) block[j], (char) b->block_field[j]);
  //
  //         }
  //         printf("\n");
  //     }
  //     number_of_conflicts++;
  //     if(num_collision_mode == false)//
  //       break;
  //   }
  // }
  // /* free the hash table contents */
  // HASH_ITER(hh, hashtable, b, tmp) {
  //   HASH_DEL(hashtable, b);
  //   free(b);
  // }

  return number_of_conflicts;
}
