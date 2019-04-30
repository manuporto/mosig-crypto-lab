#include "cbc.h"
#include "tczero.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <functional>
#include <unordered_set>
#include <unordered_map>

bool debug = false;
bool show_conflicts = false;//set to true if want to display conflicting blocks and their XOR
bool count_collision_mode = false; //set to true to get the total number of collisions in a given ciphertext



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
  uint64_t x[2] = {0};
  uint64_t iv[2] = {0};
  uint64_t iv_temp[2] = {0};
  // First we generate the IV and we prepend it to the ciphertext
  generate_iv(iv);
  if(debug)
    printf("\n IVs: %x %x ", iv[0], iv[1]);

  uint64_t masks[8] = {0x00000000000000FF, 0x000000000000FFFF,
                       0x0000000000FFFFFF, 0x00000000FFFFFFFF,
                       0x000000FFFFFFFFFF, 0x0000FFFFFFFFFFFF,
                       0x00FFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
  iv[0] = iv[0] & masks[HALF_BLOCK_SIZE/8 - 1];
  iv[1] = iv[1] & masks[HALF_BLOCK_SIZE/8 - 1];


  if(debug)
    printf("\n IVs: %x %x ", iv[0], iv[1]);
  Uint64toUint8Arr(ct, iv[0], 0, 8);
  Uint64toUint8Arr(ct, iv[1], 8, 8);
  for (size_t i = 0; i * (HALF_BLOCK_SIZE/8) < plen; i += 2) {
    x[0] = Uint8ArrtoUint64(pt, (HALF_BLOCK_SIZE/8) * i, HALF_BLOCK_SIZE/8);
    x[1] = Uint8ArrtoUint64(pt, (HALF_BLOCK_SIZE/8) * (i + 1), HALF_BLOCK_SIZE/8);

    if(debug)
      printf("\nx before encryption and XOR IV: %x %x ", x[0], x[1]);
    x[0] ^= iv[0];
    x[1] ^= iv[1];

    if(debug)
      printf("\nx before encryption: %x %x ", x[0], x[1]);
    tc0_encrypt(x, key);
    if(debug)
      printf("\nx after encryption: %x %x ", x[0], x[1]);

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
  uint64_t x[2] = {0};
  uint64_t iv[2] = {0};
  uint64_t next_iv[2] = {0};
  // We extract the IV prepended to the ciphertext
  iv[0] = Uint8ArrtoUint64(ct, 0, 8);
  iv[1] = Uint8ArrtoUint64(ct, 8, 8);
  if(debug)
    printf("\n IVs: %x %x ", iv[0], iv[1]);

  for (size_t i = 16; i < clen; i += 2 *  (HALF_BLOCK_SIZE/8)) {
    // We need to offset the ciphertext by 16 bytes becaues of the IV
    x[0] = Uint8ArrtoUint64(ct, i, HALF_BLOCK_SIZE/8);
    x[1] = Uint8ArrtoUint64(ct, (i + HALF_BLOCK_SIZE/8), HALF_BLOCK_SIZE/8);
    next_iv[0] = x[0];
    next_iv[1] = x[1];

    if(debug)
        printf("\nx before decryption: %x %x ", x[0], x[1]);

    tc0_decrypt(x, key);
    if(debug)
      printf("\nx after decryption: %x %x ", x[0], x[1]);
    x[0] ^= iv[0];
    x[1] ^= iv[1];

    iv[0] = next_iv[0];
    iv[1] = next_iv[1];
        if(debug)
          printf("\nx after decryption and XOR IV: %x %x ", x[0], x[1]);

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
}

void to_block(uint8_t *block, size_t BLOCK_SIZE, uint8_t *ct, uint32_t offset){
  for (size_t i = 0; i < BLOCK_SIZE; i++) {
    block[i] = ct[offset + i];
  }
}

void xor_blocks(uint8_t *block1, uint8_t *block2, uint8_t *xored_block, size_t number_of_chars){
  for (size_t i = 0; i < number_of_chars; i++) {
    xored_block[i] = block1[i] ^ block2[i];
  }
}

uint64_t hash(const uint8_t *block, size_t BLOCK_SIZE){
    uint64_t h = 0;
    for (size_t i = 0; i < BLOCK_SIZE; i++) {
       h = h << 1 ^ block[i];
     }
    return h;
}

uint64_t attack(uint8_t *ct, size_t ctlen){
  std::unordered_map<uint64_t, size_t> hash_map;

  size_t BLOCK_SIZE = HALF_BLOCK_SIZE * 2;
  uint64_t number_of_conflicts = 0;
  for (size_t i = 16; i < ctlen; i += BLOCK_SIZE/8) { //start from 16 to avoid IVs
    uint8_t block[BLOCK_SIZE/8] = {0};
    to_block(block, BLOCK_SIZE/8, ct, i);
    uint64_t hashed_value = 0;
    //compute hash of the current block
    hashed_value = std::hash<std::string>{}(std::string( block, block + (BLOCK_SIZE/8) ));

    //find conflicts
    auto conflict = hash_map.find(hashed_value);
    if( conflict == hash_map.end()){ //if no conflicts, add new value
      hash_map.insert(std::make_pair(hashed_value, i));
    }
    else{
      if(show_conflicts){//set to true if want to display conflicting blocks and their XOR
        uint8_t xored_block[BLOCK_SIZE/8] = {0};
        std::pair<uint64_t, size_t> p = *conflict;
        size_t index2 = std::get<1>(p);
        uint8_t block1[BLOCK_SIZE/8] = {0};
        uint8_t block2[BLOCK_SIZE/8] = {0};

        //we need to move the index two blocks before the actual one, this works also for the IVs
        to_block(block1, BLOCK_SIZE/8, ct, i - 2 * (BLOCK_SIZE/8));
        to_block(block2, BLOCK_SIZE/8, ct, index2  - 2 * (BLOCK_SIZE/8));
        //xor the blocks and print them
        xor_blocks(block, block2, xored_block, BLOCK_SIZE/8);
        printf("Collision detected between blocks: %d and %d\n", i, index2);
        for (size_t j = 0; j < BLOCK_SIZE/8; j++) {
          printf("%u %u |%u    ", block1, block2, xored_block[j]);
        }
      }
      number_of_conflicts++;
      if(count_collision_mode == false)//set to true to get the total number of collisions in a given ciphertext
      break;
    }
  }
  return number_of_conflicts;
}
