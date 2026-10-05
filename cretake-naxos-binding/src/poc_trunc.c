/* deterministic PoC: unauthenticated short m1 to K2S responder; and short m2 to K2S/S2S initiator */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KEX_AlgorithmInstance.h"
#include "drng.h"
#include "cretake_params.h"
DRNG_ctx drng_algorithm;
int main(int argc,char**argv){
  unsigned long long L=strtoull(argv[1],0,10); const char*which=argv[2];
  unsigned long long pl=kex_get_pk_len_bytes(), sl=kex_get_sk_len_bytes(), stal=kex_get_sta_len_bytes(), stbl=kex_get_stb_len_bytes(), ssl=kex_get_ss_len_bytes(), tot=kex_get_total_msg_len_bytes();
  unsigned char *pka=malloc(pl),*ska=malloc(sl),*pkb=malloc(pl),*skb=malloc(sl),*sta=malloc(stal),*stb=malloc(stbl+256),*m1=malloc(tot),*m2=malloc(tot+256),*ss=malloc(ssl);
  unsigned long long a,b,c,d,e,f,g,h,i; unsigned char seed[64]={7};
  init_random_number(&drng_algorithm, seed, 64);
  kex_init_a(pka,&a,ska,&b,sta,&c); kex_init_b(pkb,&d,skb,&e,stb,&f);
  kex_generate_pass1_msg_a(ska,b,pkb,d,sta,&c,m1,&g);
  if(!strcmp(which,"m1")){ unsigned char*x=malloc(L); memcpy(x,m1,L<g?L:g);
    printf("feeding %llu-byte m1 (honest %llu) to pass2...\n",L,g); fflush(stdout);
    int r=kex_generate_pass2_msg_b(skb,e,pka,a,x,L,stb,&f,m2,&h); printf("pass2 rc=%d SURVIVED\n",r); }
  else { int r=kex_generate_pass2_msg_b(skb,e,pka,a,m1,g,stb,&f,m2,&h); if(r<0)return 1;
    unsigned char*x=malloc(L); memcpy(x,m2,L<h?L:h);
    printf("feeding %llu-byte m2 (honest %llu) to derive_a...\n",L,h); fflush(stdout);
    r=kex_derive_ss_a(ska,b,pkb,d,x,L,sta,c,ss,&i); printf("derive_a rc=%d SURVIVED\n",r); }
  return 0;}
