/* uBlock-256/256 test vector (from Crypto-TII CLAASP ublock_block_cipher.py docstring, "Ublock 256/256") */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "ublock.h"
static int hx(const char*s,uint8_t*o,int n){for(int i=0;i<n;i++)sscanf(s+2*i,"%2hhx",&o[i]);return 0;}
int main(void){
  uint8_t p[32],k[32],c[32],e[32];
  hx("0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f",p,32);
  hx("0123456789abcdeffedcba9876543210000102030405060708090a0b0c0d0e0f",k,32);
  hx("d8e9351c5f4d27ea842135ca1640ad4b0ce119bc25c03e7c329ea8fe93e7bdfe",e,32);
  ublock256_key_t ks; ublock256_set_key(k,&ks); ublock256_256_encrypt(p,c,&ks);
  printf("got      ");for(int i=0;i<32;i++)printf("%02x",c[i]);printf("\n");
  printf("expected d8e9351c5f4d27ea842135ca1640ad4b0ce119bc25c03e7c329ea8fe93e7bdfe\n");
  printf("uBlock-256/256 KAT: %s\n", memcmp(c,e,32)?"FAIL":"PASS");
  return 0;}
