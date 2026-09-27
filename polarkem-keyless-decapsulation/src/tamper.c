#include <stdio.h>
#include <string.h>
#include "KEM_AlgorithmInstance.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
int main(){unsigned char pk[8192],sk[8192],ct[4096],ss[64],ss2[64];unsigned long long a,b,c,d,e;
 unsigned char seed[64]={1}; init_random_number(&drng_algorithm, seed, 64);
 int bad=0,tam=0; for(int t=0;t<200;t++){kem_keygen(pk,&a,sk,&b);kem_enc(pk,a,ss,&c,ct,&d);kem_dec(sk,b,ct,d,ss2,&e); if(memcmp(ss,ss2,c))bad++; ct[20]^=1; kem_dec(sk,b,ct,d,ss2,&e); if(!memcmp(ss,ss2,c))tam++;}
 printf("200 trials: decaps mismatches=%d, tampered-accepted=%d\n",bad,tam);}
