#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
DRNG_ctx drng_algorithm;
int main(int argc,char**argv){
  size_t PL=sig_get_pk_len_bytes(),SL=sig_get_sk_len_bytes(),NL=sig_get_sn_len_bytes();
  unsigned char *pk=malloc(PL),*sk=malloc(SL),*sn=malloc(NL); unsigned long long pl,sl,snl; unsigned char m[64]={0};
  unsigned char seed[64]={1}; init_random_number(&drng_algorithm,seed,64);
  sig_keygen(pk,&pl,sk,&sl); sig_sign(sk,sl,m,64,sn,&snl);
  int mode=atoi(argv[1]);
  if(mode==1){ unsigned char*s2=malloc(100); memcpy(s2,sn,100); printf("verify 100-byte sig buffer (declared 100)...\n"); fflush(stdout);
    printf("ret=%d\n",sig_verify(pk,pl,s2,100,m,64)); }
  if(mode==2){ unsigned char*p2=malloc(20); memcpy(p2,pk,20); printf("verify with 20-byte pk buffer (declared 20)...\n"); fflush(stdout);
    printf("ret=%d\n",sig_verify(p2,20,sn,snl,m,64)); }
  if(mode==3){ printf("verify with m_len = 2^64-%d ...\n",SIG_SALT_BITS/8); fflush(stdout);
    printf("ret=%d\n",sig_verify(pk,pl,sn,snl,m,(unsigned long long)(0-(uint64_t)(SIG_SALT_BITS/8)))); }
  return 0; }
