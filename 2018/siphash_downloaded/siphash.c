#include "siphash.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
	uint64_t k[] = {0x0706050403020100, 0x0f0e0d0c0b0a0908};
	uint64_t k_2[] = {0, 0};
	uint8_t m[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
	uint64_t res_1 = siphash24(m, 8, k);
	printf("Res 1: %#8lx\n", res_1);


	return 0;
} /* main() */
