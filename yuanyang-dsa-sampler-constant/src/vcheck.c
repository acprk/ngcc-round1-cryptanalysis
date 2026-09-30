#include <stdio.h>
#include <stdlib.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#include "yuanyang_inner.h"
DRNG_ctx drng_algorithm;
int main(){unsigned long long pkl=sig_get_pk_len_bytes(),skl=sig_get_sk_len_bytes(),snl=sig_get_sn_len_bytes();
 unsigned char *pk=malloc(pkl),*sk=malloc(skl),*sn=malloc(snl),seed[48]={3}; init_random_number(&drng_algorithm,seed,48);
 int ok=0,tot=0; for(int k=0;k<3;k++){ if(sig_keygen(pk,&pkl,sk,&skl)) {printf("keygen fail\n");continue;}
 for(int i=0;i<200;i++){unsigned char m[8]={i,k}; unsigned long long L=snl; if(yuanyang_sign_core(sk,skl,m,8,sn,&L)) continue; tot++; ok+= yuanyang_verify_core(pk,pkl,sn,L,m,8)==0;}}
 printf("verified %d/%d\n",ok,tot);}
