/* Pass a ciphertext buffer ONE BYTE shorter than KEM_CIPHERTEXTBYTES to kem_dec,
 * declaring the true (larger) length. If kem_dec honoured ct_len_bytes it would be
 * safe; it ignores it and reads KEM_CIPHERTEXTBYTES -> OOB read past the buffer. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include HDR
DRNG_ctx drng_algorithm;
int main(void){
  unsigned long long pl=kem_get_pk_len_bytes(),sl=kem_get_sk_len_bytes(),cl=kem_get_ct_len_bytes(),ssl=kem_get_ss_len_bytes(),t;
  unsigned char *pk=malloc(pl),*sk=malloc(sl),*ss=malloc(ssl),*ss2=malloc(ssl);
  unsigned char *ct_full=malloc(cl);
  unsigned char seed[64]; for(int j=0;j<64;j++) seed[j]=j+1;
  init_random_number(&drng_algorithm,seed,64);
  kem_keygen(pk,&t,sk,&t); kem_enc(pk,pl,ss,&t,ct_full,&t);
  /* exact-size heap buffer minus 1 byte, but tell kem_dec the full length */
  unsigned char *ct_short=malloc(cl-1); memcpy(ct_short,ct_full,cl-1);
  fprintf(stderr,"calling kem_dec with a %llu-byte buffer, declared len=%llu\n",cl-1,cl);
  kem_dec(sk,sl,ct_short,cl,ss2,&t);   /* reads ct_short[cl-1] -> OOB */
  printf("returned (no ASAN trap?) \n");
  return 0;
}
