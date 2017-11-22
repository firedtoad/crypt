#ifndef CRYPT_H
#define CRYPT_H 1
#include<stdint.h>
#include<stdlib.h>
#define SMALL_CHUNK 256
#define G 5
void Hash(const char * str, int sz, uint8_t key[8]);
int Randomkey(char tmp[8]);
void des_crypt(const uint32_t SK[32], const uint8_t input[8], uint8_t output[8]);
void des_main_ks(uint32_t SK[32], const uint8_t key[8]);
void hmac(uint32_t x[2], uint32_t y[2], uint32_t result[2]);
uint64_t mul_mod_p(uint64_t a, uint64_t b);
uint64_t pow_mod_p(uint64_t a, uint64_t b);
uint64_t powmodp(uint64_t a, uint64_t b);
#endif 

