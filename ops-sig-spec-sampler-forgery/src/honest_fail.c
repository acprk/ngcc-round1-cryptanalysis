/* Honest KeyGen->Sign->Verify against the linked rounding (spec Alg.30/32 vs reference).
 * All-public loop; no attack.  Reports the fraction of HONEST signatures the verifier rejects. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "sign.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
int main(int argc,char**argv){
  int keys=argc>1?atoi(argv[1]):20, per=argc>2?atoi(argv[2]):100;
  uint8_t s48[48]; memset(s48,7,48); if(argc>3) s48[0]=(uint8_t)atoi(argv[3]);
  init_random_number(&drng_algorithm,s48,48);
  static uint8_t pk[CRYPTO_PUBLICKEYBYTES],sk[CRYPTO_SECRETKEYBYTES],sig[CRYPTO_BYTES]; uint8_t m[33];
  long tot=0,bad=0;
  for(int k=0;k<keys;k++){ crypto_sign_keypair(pk,sk);
    for(int i=0;i<per;i++){ size_t sl; get_random_number(&drng_algorithm,m,33*8);
      crypto_sign_signature(sig,&sl,m,33,NULL,0,sk); tot++;
      if(crypto_sign_verify(sig,sl,m,33,NULL,0,pk)) bad++; } }
  printf("N=%d K=%d gamma2=(q-1)/%d : honest signatures=%ld  verify-FAILURES=%ld  (%.2f%%)\n",
         N,K,(Q-1)/GAMMA2,tot,bad,100.0*bad/tot);
  return 0;
}
