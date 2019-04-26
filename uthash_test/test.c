#include <string.h>  /* strcpy */
#include <stdlib.h>  /* malloc */
#include <stdio.h>   /* printf */
#include "../res/uthash.h"

#define HALF_BLOCK_SIZE 2

struct uint8_t_hashable {
    char block_field[HALF_BLOCK_SIZE * 2];             /* key (string is WITHIN the structure) */
    UT_hash_handle hh;         /* makes this structure hashable */
};

void to_block(char *block, size_t block_size, uint8_t *ct, uint32_t offset){
  for (size_t i = 0; i < block_size; i++) {
    block[i] = ct[offset + i];
  }
}

int main(int argc, char *argv[]) {
    struct uint8_t_hashable *s, *tmp, *users = NULL;
    uint8_t block_long[] = "01aa01aa";
    size_t block_size = HALF_BLOCK_SIZE * 2;

    for (int i = 0; i<2; ++i) {
        char block[block_size];
        to_block(block, block_size, block_long, i*block_size);

        HASH_FIND_STR( users, block, s);
        if(s == NULL){
            s = (struct uint8_t_hashable *)malloc(sizeof *s);
            strcpy(s->block_field, block);
            HASH_ADD_STR( users, block_field, s );
            printf("adding %s\n", block);

        }
        else{
            printf("conflict\n");
        }
    }

      for(s=users; s != NULL; s=(struct uint8_t_hashable*)(s->hh.next)) {
          printf("block %s\n", s->block_field);
      }

    /* free the hash table contents */
    HASH_ITER(hh, users, s, tmp) {
      HASH_DEL(users, s);
      free(s);
    }
    return 0;
}


uint64_t attack(uint8_t *ct, size_t ctlen){
  struct uint8_t_hashable *tmp, *b, *hashtable = NULL;
  uint8_t block_long[] = "01aa01aa";
  size_t block_size = HALF_BLOCK_SIZE * 2;

  // for (int i = 2; i<4; ++i) {
  //     char block[block_size];
  //     to_block(block, block_size, ct, i*block_size);
  //
  //     HASH_FIND_STR( hashtable, block, b);
  //     if(b == NULL){
  //         b = (struct uint8_t_hashable *)malloc(sizeof *b);
  //         strcpy(b->block_field, block);
  //         HASH_ADD_STR( hashtable, block_field, b );
  //         printf("adding %s\n", block);
  //
  //     }
  //     else{
  //         printf("conflict\n");
  //     }
  // }
  // return 0;

  for (size_t i = 2; i < ctlen/block_size; i+=1) {
    char block[block_size] = {0};
    to_block(block, block_size, ct, i * block_size);
    for (size_t j = 0; j < block_size; j++) {
      printf("%u", block[j] );
    }
    printf("  i %u\n",i);

    HASH_FIND_STR( hashtable, block, b);
    printf("  i %u\n",i);



    if( b==NULL ){
        b = (struct uint8_t_hashable *)malloc(sizeof *b);
        strcpy(b->block_field, block);
        HASH_ADD_STR( hashtable, block_field, b );
        printf("adding %s\n", block);
    }
    else{//TODO conflict
      printf("Conflict detected between blocks: \n");
    }
  }

      for(b=hashtable; b != NULL; b=(struct uint8_t_hashable*)(b->hh.next)) {
          printf("block %s\n", b->block_field);
      }

/* free the hash table contents */
HASH_ITER(hh, hashtable, b, tmp) {
  HASH_DEL(hashtable, b);
  free(b);
  }

  return 0;
}
