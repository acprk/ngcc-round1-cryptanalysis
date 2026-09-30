/* Sampler microbenchmark. Links sample.c (instrumented for mode 'count',
 * unmodified for mode 'time'). Drives exactly what pke_enc does:
 * sample_sp(r1,64,S1); sample_e12(r2,64,E1,E2) on random 64+64-byte seeds.
 * count: sampler_bench count N seeds.bin out.csv   (generates seeds)
 * time : sampler_bench time seeds.bin sel.txt reps out.csv */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>
#include "parameters.h"
#include "scloudplus_param_common.h"
#include "sample.h"
#include "random.h"
static uint16_t S1[(size_t)scloudplus_mbar*scloudplus_m] __attribute__((aligned(32)));
static uint16_t E1[(size_t)scloudplus_mbar*scloudplus_n] __attribute__((aligned(32)));
static uint16_t E2[(size_t)scloudplus_mbar*scloudplus_nbar] __attribute__((aligned(32)));
static inline uint64_t t0(void){_mm_lfence();uint64_t x=__rdtsc();_mm_lfence();return x;}
static inline uint64_t t1(void){unsigned a;uint64_t x=__rdtscp(&a);_mm_lfence();return x;}
#ifdef COUNT_MODE
extern unsigned long long g_xof_refills, g_rej_batches, g_straddle;
#endif
static uint64_t rng=0x1234567; static uint64_t xs(void){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
int main(int argc,char**argv){
#ifdef COUNT_MODE
  int N=atoi(argv[2]); uint8_t*seeds=malloc(128*(size_t)N); randombytes(seeds,128*N);
  FILE*o=fopen(argv[3],"wb");fwrite(seeds,128,N,o);fclose(o);
  o=fopen(argv[4],"w");fprintf(o,"idx,batches,xof_refills,straddles\n");
  for(int i=0;i<N;i++){g_xof_refills=g_rej_batches=g_straddle=0;
    sample_sp(seeds+128*i,64,S1); sample_e12(seeds+128*i+64,64,E1,E2);
    fprintf(o,"%d,%llu,%llu,%llu\n",i,g_rej_batches,g_xof_refills,g_straddle);}
  fclose(o);
#else
  FILE*f=fopen(argv[2],"rb");fseek(f,0,SEEK_END);long n=ftell(f)/128;fseek(f,0,SEEK_SET);
  uint8_t*seeds=malloc(128*n);if(fread(seeds,128,n,f)!=(size_t)n)return 1;fclose(f);
  f=fopen(argv[3],"r");int K=0,idx[4096],lab[4096];while(K<4096&&fscanf(f,"%d %d",&idx[K],&lab[K])==2)K++;fclose(f);
  int R=atoi(argv[4]);FILE*o=fopen(argv[5],"w");fprintf(o,"rep,idx,label,cycles\n");int ord[4096];
  for(int r=0;r<R;r++){for(int i=0;i<K;i++)ord[i]=i;
    for(int i=K-1;i>0;i--){int j=xs()%(i+1);int t=ord[i];ord[i]=ord[j];ord[j]=t;}
    for(int p=0;p<K;p++){int i=ord[p];uint8_t*s=seeds+128*idx[i];
      uint64_t a=t0(); sample_sp(s,64,S1); sample_e12(s+64,64,E1,E2); uint64_t b=t1();
      fprintf(o,"%d,%d,%d,%llu\n",r,idx[i],lab[i],(unsigned long long)(b-a));}}
  fclose(o);
#endif
  return 0;}
