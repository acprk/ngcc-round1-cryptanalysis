#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
int main(){
  unsigned char seed[64]={7}; init_random_number(&drng_algorithm, seed, 64);
  unsigned long long pkl,skl,snl;
  unsigned char *pk=malloc(sig_get_pk_len_bytes());
  unsigned char *sk=malloc(sig_get_sk_len_bytes());
  unsigned char *sn=malloc(sig_get_sn_len_bytes());
  unsigned char m[8]="message";
  if(sig_keygen(pk,&pkl,sk,&skl)){printf("keygen fail\n");return 1;}
  if(sig_sign(sk,skl,m,7,sn,&snl)){printf("sign fail\n");return 1;}
  int honest=sig_verify(pk,pkl,sn,snl,m,7);
  // tamper: flip a byte in the sparse-e region (after 12B param + 16B r)
  sn[40]^=0xFF; sn[100]^=0xFF; sn[200]^=0x0F;
  int tampered=sig_verify(pk,pkl,sn,snl,m,7);
  // fully random signature buffer (garbage e), keep header+r valid
  for(unsigned long long i=28;i<snl;i++) sn[i]=(unsigned char)(i*131+7);
  int garbage=sig_verify(pk,pkl,sn,snl,m,7);
  // wrong message
  unsigned char m2[8]="XXXXXXX";
  int wrongmsg=sig_verify(pk,pkl,sn,snl,m2,7);
  printf("API sig_verify: honest=%d tampered=%d garbage=%d wrongmsg=%d (0=ACCEPT)\n",honest,tampered,garbage,wrongmsg);
  return 0;
}
