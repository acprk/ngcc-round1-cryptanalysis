/* Offline counting harness (links INSTRUMENTED sample_count.c; never timed).
 * usage: gen_count N outprefix
 * writes outprefix_{pk,sk,ct}.bin and outprefix_counts.csv */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KEM_AlgorithmInstance.h"
extern unsigned long long g_xof_refills, g_rej_batches, g_straddle;
static void wr(const char *pre,const char *suf,const void *p,size_t n){char f[512];snprintf(f,512,"%s_%s",pre,suf);FILE*o=fopen(f,"wb");fwrite(p,1,n,o);fclose(o);}
int main(int argc,char**argv){
  int N=atoi(argv[1]); const char*pre=argv[2];
  unsigned long long pkl=kem_get_pk_len_bytes(),skl=kem_get_sk_len_bytes(),ssl=kem_get_ss_len_bytes(),ctl=kem_get_ct_len_bytes();
  unsigned char *pk=malloc(pkl),*sk=malloc(skl),*ss=malloc(ssl),*ss1=malloc(ssl),*cts=malloc(ctl*(size_t)N);
  unsigned long long a=pkl,b=skl,c,d;
  if(kem_keygen(pk,&a,sk,&b)){fprintf(stderr,"keygen\n");return 1;}
  wr(pre,"pk.bin",pk,pkl); wr(pre,"sk.bin",sk,skl);
  char f[512];snprintf(f,512,"%s_counts.csv",pre);FILE*o=fopen(f,"w");
  fprintf(o,"idx,batches,xof_refills,straddles,dec_batches_only\n");
  int bad=0;
  for(int t=0;t<N;t++){unsigned char*ct=cts+(size_t)t*ctl; c=ctl;d=ssl;
    kem_enc(pk,pkl,ss,&d,ct,&c);
    g_xof_refills=g_rej_batches=g_straddle=0; d=ssl;
    kem_dec(sk,skl,ct,ctl,ss1,&d);
    if(memcmp(ss,ss1,ssl))bad++;
    fprintf(o,"%d,%llu,%llu,%llu,%llu\n",t,g_rej_batches,g_xof_refills,g_straddle,g_rej_batches);}
  fclose(o); wr(pre,"ct.bin",cts,ctl*(size_t)N);
  fprintf(stderr,"N=%d ss_mismatch=%d ctl=%llu skl=%llu\n",N,bad,ctl,skl);
  return 0;}
