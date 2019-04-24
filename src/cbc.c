#include "cbc.h"
#include "tczero.h"
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

const size_t MAX_ENCRYPTIONS = 1;
// We initialize the number_of_encryptions to the same value
// of MAX_ENCRYPTIONS to force the initial generation of the IV
size_t number_of_encryptions = 1;
uint64_t current_iv[2] = {};

// Function to get random data and put it in buf.
// Note getrandom function from linux/random.h was not used because I do not posses a new enough kernel (Manuel)
ssize_t get_random(void *buf, size_t buflen) {
  int randomData = open("/dev/urandom", O_RDONLY);
    if (randomData < 0) {
      // something went wrong
      return -1;
    } else {
      return read(randomData, buf, buflen);
    }
}

void generate_iv(uint64_t iv[]) {
  if (number_of_encryptions < MAX_ENCRYPTIONS) {
    current_iv[0]++;
    current_iv[1]++;
    number_of_encryptions++;
  } else {
    // Generate a totally new random IV
    get_random(current_iv, sizeof(uint64_t) * 2);
    number_of_encryptions = 0;
  }
  iv[0] = current_iv[0];
  iv[1] = current_iv[1];
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

    printf("\nx after encryption: %lu %lu ", x[0], x[1]);

    // We need to offset the ciphertext by 16 bytes becaues of the IV
    Uint64toUint8Arr(ct, x[0], 8 * (i + 2));
    Uint64toUint8Arr(ct, x[1], 8 * (i + 3));

    iv[0] = x[0];
    iv[1] = x[1];
  }
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

uint64_t attack(uint8_t *ct, size_t ctlen){}

int main(int argc, char const *argv[]) {

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

    printf("encryption (IV not included):\n");
    for (size_t i = 16; i < clen; i++) {
      printf("%u ", ciphertext[i]);
    }

    cbc_dec(key, ciphertext, plaintext2, plen);
    printf("\ndectyption:\n");
    for (size_t i = 0; i < plen; i++) {
      printf("%c", plaintext2[i]);
    }
  return 0;
}
