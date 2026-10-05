#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KEX_AlgorithmInstance.h"
#include "drng.h"
#include "cretake_params.h"
DRNG_ctx drng_algorithm;
int main(void){
  unsigned long long pl=kex_get_pk_len_bytes(), sl=kex_get_sk_len_bytes(), stal=kex_get_sta_len_bytes();
  unsigned char *pka=calloc(pl,1),*ska=calloc(sl,1),*sta=calloc(stal+64,1); unsigned long long a,b,c;
  unsigned char seed[64]={3}; init_random_number(&drng_algorithm,seed,64);
  kex_init_a(pka,&a,ska,&b,sta,&c);
  unsigned long long i=0; while(i<a&&i<b&&pka[i]==ska[i])i++;
  printf("%s pk=%llu sk=%llu LCP(pk,sk)=%llu absorbed_sk_bytes=%llu(=(%d+%d)/8-%d) absorbed_is_public=%s\n",
    ALGORITHM_INSTANCE,a,b,i,(unsigned long long)((SEED_BYTES+SKI_LEN)/8-SEED_BYTES),SEED_BYTES,SKI_LEN,SEED_BYTES,
    ((SEED_BYTES+SKI_LEN)/8-SEED_BYTES)<=i?"YES":"no");
  return 0;}
