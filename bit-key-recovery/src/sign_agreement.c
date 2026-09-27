/* Diagnostic for measure_sign_agreement.sh: P(sgn<z0,c> == beta) under the victim key.
 * Links against an instrumented copy of the reference that exports bit_last_b. */
#include <stdio.h>
#include <stdlib.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "params.h"
DRNG_ctx drng_algorithm; extern int bit_last_b;
int main(int argc,char**argv){ long T=atol(argv[1]);
  unsigned char kseed[64]; for(int i=0;i<64;i++)kseed[i]=(unsigned char)(0xA7*i+0x13);
  init_random_number(&drng_algorithm,kseed,64);
  unsigned long long pkl=sig_get_pk_len_bytes(),skl=sig_get_sk_len_bytes(),snl=sig_get_sn_len_bytes();
  unsigned char*pk=malloc(pkl),*sk=malloc(skl),*sn=malloc(snl); sig_keygen(pk,&pkl,sk,&skl);
  unsigned char m[32]; long agree=0,done=0,zero=0; srand(1);
  for(long t=0;t<T;t++){ for(int i=0;i<32;i++)m[i]=rand(); unsigned long long s=snl;
    if(sig_sign(sk,skl,m,32,sn,&s))continue;
    polyvecm1 z1;polyveck h;unsigned char ch[BIT_CHALLENGEBYTES];poly c; unpack_sig(&z1,&h,ch,sn); poly_challenge(&c,ch);
    long dot=0; for(int j=0;j<BIT_N;j++) dot+=(long)z1.vec[0].coeffs[j]*c.coeffs[j];
    int sigma = dot>=0?1:-1, beta = bit_last_b?-1:1; if(dot==0)zero++;
    agree += (sigma==beta); done++; }
  printf("sigs %ld  P(sigma==beta)=%.4f  (<z0,c>==0 in %ld sigs)\n",done,(double)agree/done,zero); return 0; }
