#ifndef __CBC_H
#define __CBC_H

#include <stdint.h>
#include <stdlib.h>

size_t cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t plen);

size_t cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t clen);

void addToBitsAtPosition(uint8_t location, uint64_t *bits, uint8_t to_be_added);

void backToArray(uint8_t *ct, uint64_t bits, size_t offset);

uint64_t Uint8ArrtoUint64 (uint8_t* var, uint32_t lowest_pos);

void Uint64toUint8Arr (uint8_t* buf, uint64_t var, uint32_t lowest_pos);


#endif
