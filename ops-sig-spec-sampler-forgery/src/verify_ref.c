/* Control: run the UNMODIFIED reference verifier (shipped, correct SampleInBall) on the forged
 * signature.  It must REJECT -- proving the forgery relies on the spec's fixed-support sampler. */
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "sign.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
int main(int c,char**v){
  static uint8_t pk[CRYPTO_PUBLICKEYBYTES], sig[CRYPTO_BYTES];
  FILE*f=fopen(v[1],"rb"); if(!f||fread(pk,1,sizeof pk,f)!=sizeof pk||fread(sig,1,CRYPTO_BYTES,f)!=CRYPTO_BYTES){printf("read err\n");return 2;} fclose(f);
  const char*m="OPS-SIG spec-literal SampleInBall forgery: this message was never signed";
  int r=crypto_sign_verify(sig,CRYPTO_BYTES,(const uint8_t*)m,strlen(m),NULL,0,pk);
  printf("reference (shipped, correct) verifier on the forged signature: verify = %d  (%s)\n",
         r, r?"REJECT -- forgery is specific to the spec's fixed-support sampler":"ACCEPT (unexpected!)");
  return r?0:1;
}
