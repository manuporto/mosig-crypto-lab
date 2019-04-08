#ifndef __CBC_H
#define __CBC_H

#include <stdint.h>
#include <stdlib.h>

size_t cbc_enc(uint64_t key[2], uint8_t *pt, uint8_t *ct, size_t plen);

size_t cbc_dec(uint64_t key[2], uint8_t *ct, uint8_t *pt, size_t clen);

#endif