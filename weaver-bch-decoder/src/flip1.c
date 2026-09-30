/* Single high-layer error injection: shift one v coefficient by ~q/2 (flip high bit of coeff 5)
   and check whether IND-CPA decryption still returns m (a BCH-protected layer must correct 1 error). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "params.h"
#include "indcpa.h"
#include "poly.h"
#include "msgenc.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
int main(void){
  uint8_t pk[WEAVER_INDCPA_PUBLICKEYBYTES], sk[WEAVER_INDCPA_SECRETKEYBYTES], ct[WEAVER_INDCPA_BYTES];
  uint8_t coins[2*WEAVER_SYMBYTES]={1}, m[WEAVER_INDCPA_MSGBYTES], mo[WEAVER_INDCPA_MSGBYTES], ec[WEAVER_SYMBYTES]={7};
  int ok=0, tot=0;
  for(int trial=0;trial<200;trial++){
    coins[1]=trial; ec[1]=trial; for(unsigned i=0;i<sizeof m;i++) m[i]=(uint8_t)(i*37+trial*11);
    indcpa_keypair_derand(pk,sk,coins); indcpa_enc(ct,m,pk,ec);
    /* decompress v, add q/2 to coefficient 5, recompress */
    poly v; poly_decompress(&v, ct+WEAVER_POLYVECCOMPRESSEDBYTES);
    v.coeffs[5] = (int16_t)((v.coeffs[5] + WEAVER_HALFQ) % WEAVER_Q);
    poly_compress(ct+WEAVER_POLYVECCOMPRESSEDBYTES,&v);
    indcpa_dec(mo,ct,sk); tot++; if(!memcmp(m,mo,sizeof m)) ok++;
  }
  printf("mode %d: 1 injected high-layer error on payload coeff 5 -> decrypted correctly %d/%d\n",WEAVER_MODE,ok,tot);
  return 0;
}
