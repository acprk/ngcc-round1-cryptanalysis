#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "drng.h"
#include "KEM_AlgorithmInstance.h"
/* Modes: 0 honest round trip | 1 timing of N honest decaps | 2 does decaps advance the global DRNG
   | 3 return-code histogram of N tampered cts | 4 one ct with byte N of c1 xor 0x5a (time) */
DRNG_ctx drng_algorithm;
static double now(){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec*1e-9;}
int main(int argc,char**argv){
  int mode=argc>1?atoi(argv[1]):0, N=argc>2?atoi(argv[2]):20;
  unsigned char seed[48]; memset(seed,7,48); init_random_number(&drng_algorithm,seed,48);
  unsigned long long pl,sl,cl,ssl;
  unsigned char *pk=malloc(kem_get_pk_len_bytes()),*sk=malloc(kem_get_sk_len_bytes()),*ct=malloc(kem_get_ct_len_bytes());
  unsigned char ss[64],ss2[64];
  kem_keygen(pk,&pl,sk,&sl);
  if(mode==0){ /* one honest enc/dec (for leak measurement) */
    kem_enc(pk,pl,ss,&ssl,ct,&cl); int r=kem_dec(sk,sl,ct,cl,ss2,&ssl);
    printf("dec ret=%d match=%d\n",r,!memcmp(ss,ss2,ssl)); fflush(stdout); }
  if(mode==1){ /* timing of honest decaps */
    for(int i=0;i<N;i++){ kem_enc(pk,pl,ss,&ssl,ct,&cl); double t0=now(); int r=kem_dec(sk,sl,ct,cl,ss2,&ssl); double t1=now();
      printf("%d %d %.4f\n",i,r,t1-t0); fflush(stdout);} }
  if(mode==2){ /* decaps consumes the global DRNG: enc after a decaps differs from enc without */
    DRNG_ctx save; kem_enc(pk,pl,ss,&ssl,ct,&cl); save=drng_algorithm;
    unsigned char *c1=malloc(cl),*c2=malloc(cl);
    kem_enc(pk,pl,ss,&ssl,c1,&cl);                 /* path A: enc directly */
    drng_algorithm=save; kem_dec(sk,sl,ct,cl,ss2,&ssl); kem_enc(pk,pl,ss,&ssl,c2,&cl); /* path B: decaps then enc */
    printf("next encapsulation identical with/without an intervening decaps: %s\n", memcmp(c1,c2,cl)?"NO (decaps advanced the shared DRNG)":"yes"); }
  if(mode==3){ /* explicit, distinguishable return codes */
    kem_enc(pk,pl,ss,&ssl,ct,&cl);
    unsigned char *t=malloc(cl);
    int hist[16]={0};
    for(int i=0;i<N;i++){ memcpy(t,ct,cl); t[(i*7919)%cl]^=1+(i%255); int r=kem_dec(sk,sl,t,cl,ss2,&ssl); hist[-r<16&&r<=0?-r:15]++; }
    for(int i=0;i<16;i++) if(hist[i]) printf("ret=-%d : %d\n",i,hist[i]); }
  if(mode==4){ /* one malformed ciphertext: flip one byte of c1, time + leak */
    kem_enc(pk,pl,ss,&ssl,ct,&cl); ct[N%cl]^=0x5a; double t0=now(); int r=kem_dec(sk,sl,ct,cl,ss2,&ssl);
    printf("malformed dec ret=%d time=%.3f\n",r,now()-t0); }
  free(pk); free(sk); free(ct);  /* harness buffers: freed so ASan reports only library leaks */
  return 0;}
