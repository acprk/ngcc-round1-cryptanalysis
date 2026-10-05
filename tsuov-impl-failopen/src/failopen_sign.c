#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
DRNG_ctx drng_algorithm;
int main(){
  size_t PL=sig_get_pk_len_bytes(),SL=sig_get_sk_len_bytes(),NL=sig_get_sn_len_bytes();
  unsigned char *pk=malloc(PL),*sk=malloc(SL),*junk=calloc(NL,1),*sn=malloc(NL); unsigned long long pl,sl,snl;
  unsigned char seed[64]={3}; init_random_number(&drng_algorithm,seed,64);
  sig_keygen(pk,&pl,sk,&sl);
  const char *mstar="attacker-chosen M*: transfer all funds";
  printf("verify(junk, M*)  = %d\n",sig_verify(pk,pl,junk,NL,(unsigned char*)mstar,strlen(mstar)));
  int rs=sig_sign(sk,sl,(unsigned char*)"x",1ULL<<62,sn,&snl);
  printf("sign(len=2^62) ret=%d ; resulting sig valid on M*? %d (0=yes)\n",rs,sig_verify(pk,pl,sn,snl,(unsigned char*)mstar,strlen(mstar)));
  /* also: sign after sign */
  const char *a="first signed message"; sig_sign(sk,sl,(unsigned char*)a,strlen(a),sn,&snl);
  sig_sign(sk,sl,(unsigned char*)"x",1ULL<<62,sn,&snl);
  printf("sign-after-sign: stale sig valid on previous message? %d (0=yes)\n",sig_verify(pk,pl,sn,snl,(unsigned char*)a,strlen(a)));
  return 0;}
