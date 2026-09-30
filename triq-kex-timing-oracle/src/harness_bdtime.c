// Timing harness: does crypto_kem_dec time depend on the BD-resample count of m'?
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "api.h"
#include "parameters.h"
#include "symmetric.h"
#include "vector.h"
#include "parsing.h"
#include "triq_pke.h"
#include "data_structures.h"

static inline uint64_t rdtsc(void){ unsigned lo,hi; __asm__ volatile("lfence\nrdtsc":"=a"(lo),"=d"(hi)); return ((uint64_t)hi<<32)|lo; }

// replicate encrypt's XOF consumption, counting BD iterations for r2 and r1
static int count_bd(const uint8_t *theta, int *it_r2, int *it_r1){
    triq_xof_ctx ctx={0}; uint32_t support[PARAM_OMEGA_MAX]; uint16_t iter; uint64_t dummy[VEC_N_SIZE_64]={0};
    xof_init(&ctx, theta, SEED_BYTES);
    for(iter=0;iter<PARAM_BD_N_MAX;iter++){ vect_generate_random_support2(&ctx,support,PARAM_OMEGA_R); if(!vect_check_bounded_density(support,PARAM_OMEGA_R,PARAM_BD_L,PARAM_BD_GAMMA)) break; }
    *it_r2=iter;
    vect_sample_fixed_weight2(&ctx,dummy,PARAM_OMEGA_E);
    for(iter=0;iter<PARAM_BD_N_MAX;iter++){ vect_generate_random_support2(&ctx,support,PARAM_OMEGA_R); if(!vect_check_bounded_density(support,PARAM_OMEGA_R,PARAM_BD_L,PARAM_BD_GAMMA)) break; }
    *it_r1=iter; return 0;
}
static int cmpu64(const void*a,const void*b){uint64_t x=*(uint64_t*)a,y=*(uint64_t*)b;return x<y?-1:x>y;}

int main(int argc,char**argv){
    int N = argc>1?atoi(argv[1]):2000; int REP = argc>2?atoi(argv[2]):15;
    uint8_t ent[48]={1},per[48]={2}; prng_init(ent,per,48,48);
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    crypto_kem_keypair(pk,sk);
    uint8_t hek[SEED_BYTES]; hash_h(hek,pk);
    // buckets by total resamples 0,1,2+
    double sum[3]={0}; int cnt[3]={0}; uint64_t *meds=malloc(sizeof(uint64_t)*N); int *tot=malloc(sizeof(int)*N);
    uint8_t *ct=malloc(CRYPTO_CIPHERTEXTBYTES); uint8_t ss[CRYPTO_BYTES], ss2[CRYPTO_BYTES];
    uint64_t t[64];
    int bad=0;
    for(int i=0;i<N;i++){
        crypto_kem_enc(ct,ss,pk);
        // recover theta: need m and salt; m unknown here -> instead decrypt to get m' (honest => m'=m)
        ciphertext_kem_t c={0}; triq_c_kem_from_string(&c.c_pke,c.salt,ct);
        uint8_t m[PARAM_SECURITY_BYTES]={0}; triq_pke_decrypt((uint64_t*)m,sk+PUBLIC_KEY_BYTES,&c.c_pke);
        uint8_t kt[SHARED_SECRET_BYTES+SEED_BYTES]; hash_g(kt,hek,m,c.salt);
        int a,b; count_bd(kt+SHARED_SECRET_BYTES,&a,&b); int T=a+b; if(T>2)T=2; tot[i]=T;
        for(int r=0;r<REP;r++){ uint64_t t0=rdtsc(); crypto_kem_dec(ss2,ct,sk); t[r]=rdtsc()-t0; }
        if(memcmp(ss,ss2,CRYPTO_BYTES)) bad++;
        qsort(t,REP,sizeof(uint64_t),cmpu64); meds[i]=t[0];
        sum[T]+=meds[i]; cnt[T]++;
    }
    printf("N=%d REP=%d mismatches=%d\n",N,REP,bad);
    for(int k=0;k<3;k++){ printf("resamples=%d%s: n=%d mean_median_cycles=%.0f\n",k,k==2?"+":"",cnt[k],cnt[k]?sum[k]/cnt[k]:0.0); }
    // separability: fraction of class-1 medians above class-0 90th percentile
    uint64_t *c0=malloc(sizeof(uint64_t)*N); int n0=0; for(int i=0;i<N;i++) if(tot[i]==0) c0[n0++]=meds[i];
    qsort(c0,n0,sizeof(uint64_t),cmpu64); uint64_t p90=c0[(int)(n0*0.9)], p99=c0[(int)(n0*0.99)];
    int above90=0,above99=0,n1=0; for(int i=0;i<N;i++) if(tot[i]>=1){n1++; above90+=meds[i]>p90; above99+=meds[i]>p99;}
    { double m0=0,m1=0,v0=0,v1=0; int k0=0,k1=0; for(int i=0;i<N;i++){ if(tot[i]==0){m0+=meds[i];k0++;} else if(tot[i]==1){m1+=meds[i];k1++;} }
      m0/=k0; m1/=k1; for(int i=0;i<N;i++){ if(tot[i]==0) v0+=(meds[i]-m0)*(meds[i]-m0); else if(tot[i]==1) v1+=(meds[i]-m1)*(meds[i]-m1);} v0=v0/k0; v1=v1/k1;
      printf("min-based: class0 mean=%.0f sd=%.0f ; class1 mean=%.0f sd=%.0f ; delta=%.0f cycles, d'=%.2f, SE(delta)=%.0f\n",m0,__builtin_sqrt(v0),m1,__builtin_sqrt(v1),m1-m0,(m1-m0)/__builtin_sqrt(v0),__builtin_sqrt(v0/k0+v1/k1)); }
    printf("class0 p90=%lu p99=%lu ; class>=1: %d/%d above p90, %d/%d above p99\n",(unsigned long)p90,(unsigned long)p99,above90,n1,above99,n1);
    return 0;
}
