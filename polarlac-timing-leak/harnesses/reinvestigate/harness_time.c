/* harness_time.c  Re-investigation timing harness for PolarLAC-Light.
   Links UNMODIFIED reference. Recomputes rejection count R offline using the
   reference's own exported poly_generate_tenary + fft_within_bound_int16, so we
   never touch/instrument src. Times kem_dec with rdtsc, pinned core, min-of-k.
   Secret key is used ONLY to build valid ciphertexts / nothing about the oracle. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "drng.h"
#include "params.h"
#include "KEM_AlgorithmInstance.h"
#include "pke.h"
#include "sample.h"
#include "fft.h"
#include "symmetric.h"

DRNG_ctx drng_algorithm;

static inline uint64_t rdtscp(void){
    unsigned lo,hi,aux;
    __asm__ __volatile__("rdtscp":"=a"(lo),"=d"(hi),"=c"(aux));
    return ((uint64_t)hi<<32)|lo;
}
static inline void lfence(void){ __asm__ __volatile__("lfence":::"memory"); }

/* Recompute rejection iteration count R that PKE_Encrypt(ct_check,pk,m,seed_enc)
   would do during decapsulation of a ciphertext that decrypts to message m. */
static int recompute_R(const uint8_t *m, const uint8_t *pk){
    uint8_t din[PKE_MESSAGE_BYTES + PKE_PUBLIC_KEY_BYTES];
    uint8_t gout[KEM_SS_BYTES + KEM_SEED_LEN_BYTES];
    memcpy(din, m, PKE_MESSAGE_BYTES);
    memcpy(din+PKE_MESSAGE_BYTES, pk, PKE_PUBLIC_KEY_BYTES);
    bit_xof((KEM_SS_BYTES+KEM_SEED_LEN_BYTES)*8ULL, din, sizeof(din)*8ULL, gout);
    const uint8_t *seed_enc = gout + KEM_SS_BYTES; /* 64 bytes */
    uint8_t nonce=0; int R=0;
    int16_t cand[RL_KEM_N];
    for(int poly=0; poly<4; poly++){          /* r.vec[0],r.vec[1],e1.vec[0],e1.vec[1] */
        for(;;){
            poly_generate_tenary(cand, seed_enc, nonce);
            nonce=(uint8_t)(nonce+1U); R++;
            if(fft_within_bound_int16(cand,(int32_t)RL_KEM_T)) break;
        }
    }
    return R;
}

static uint64_t time_dec_mink(uint8_t*sk,unsigned long long skl,uint8_t*ct,unsigned long long ctl,int k){
    uint8_t ss[64]; unsigned long long sl; uint64_t best=~0ULL;
    for(int i=0;i<k;i++){
        lfence(); uint64_t t0=rdtscp(); lfence();
        kem_dec(sk,skl,ct,ctl,ss,&sl);
        lfence(); uint64_t t1=rdtscp(); lfence();
        uint64_t d=t1-t0; if(d<best)best=d;
    }
    return best;
}

static int cmp_u64(const void*a,const void*b){ uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b; return (x>y)-(x<y); }

int main(int argc,char**argv){
    int NKEYS = argc>1?atoi(argv[1]):3;
    int NCT   = argc>2?atoi(argv[2]):2000;   /* ciphertexts per key */
    int MINK  = argc>3?atoi(argv[3]):15;     /* reps per ct, take min */
    uint8_t drng_seed[48]; for(int i=0;i<48;i++)drng_seed[i]=(uint8_t)(i*7+1);
    init_random_number(&drng_algorithm,drng_seed,sizeof(drng_seed));

    /* aggregate stats per R bucket, across all keys */
    enum{RMAX=12};
    /* store per (R) all min-cycle samples for percentile */
    uint64_t *buf[RMAX]; long cnt[RMAX]={0}; long cap[RMAX];
    for(int r=0;r<RMAX;r++){cap[r]=NKEYS*NCT+16; buf[r]=malloc(sizeof(uint64_t)*cap[r]);}
    long Rdist[RMAX]={0}; long total=0;

    for(int key=0;key<NKEYS;key++){
        static uint8_t pk[PKE_PUBLIC_KEY_BYTES+64], sk[KEM_SK_BYTES+64];
        unsigned long long pkl,skl;
        if(kem_keygen(pk,&pkl,sk,&skl)!=0){fprintf(stderr,"keygen fail\n");return 1;}
        /* warm up */
        {uint8_t ss[64],ct[PKE_CIPHERTEXT_BYTES];unsigned long long sl,cl;
         kem_enc(pk,pkl,ss,&sl,ct,&cl);
         for(int w=0;w<2000;w++){uint8_t s2[64];unsigned long long s2l;kem_dec(sk,skl,ct,cl,s2,&s2l);} }
        for(int c=0;c<NCT;c++){
            /* build a valid ciphertext for a fresh random m, and know m */
            uint8_t m[PKE_MESSAGE_BYTES]; uint8_t ss[64]; uint8_t seed_enc[KEM_SEED_LEN_BYTES];
            get_random_number(&drng_algorithm,m,PKE_MESSAGE_BYTES*8ULL);
            uint8_t din[PKE_MESSAGE_BYTES+PKE_PUBLIC_KEY_BYTES];
            uint8_t gout[KEM_SS_BYTES+KEM_SEED_LEN_BYTES];
            memcpy(din,m,PKE_MESSAGE_BYTES); memcpy(din+PKE_MESSAGE_BYTES,pk,PKE_PUBLIC_KEY_BYTES);
            bit_xof((KEM_SS_BYTES+KEM_SEED_LEN_BYTES)*8ULL,din,sizeof(din)*8ULL,gout);
            memcpy(seed_enc,gout+KEM_SS_BYTES,KEM_SEED_LEN_BYTES);
            uint8_t ct[PKE_CIPHERTEXT_BYTES];
            PKE_Encrypt(ct,pk,m,seed_enc);
            int R=recompute_R(m,pk); if(R>=RMAX)R=RMAX-1;
            uint64_t cyc=time_dec_mink(sk,skl,ct,PKE_CIPHERTEXT_BYTES,MINK);
            buf[R][cnt[R]++]=cyc; Rdist[R]++; total++;
        }
    }
    printf("# PolarLAC-Light decap timing vs rejection count R (min-of-%d, %d keys, %ld cts)\n",MINK,NKEYS,total);
    printf("# R    count     frac      median_cyc   p10        p90        IQR\n");
    for(int r=0;r<RMAX;r++){
        if(cnt[r]<1)continue;
        qsort(buf[r],cnt[r],sizeof(uint64_t),cmp_u64);
        uint64_t med=buf[r][cnt[r]/2];
        uint64_t p10=buf[r][(long)(cnt[r]*0.10)];
        uint64_t p90=buf[r][(long)(cnt[r]*0.90)];
        uint64_t q1=buf[r][(long)(cnt[r]*0.25)];
        uint64_t q3=buf[r][(long)(cnt[r]*0.75)];
        printf("%3d %8ld  %7.4f   %9llu  %9llu  %9llu  %8llu\n",
            r,cnt[r],(double)Rdist[r]/total,(unsigned long long)med,
            (unsigned long long)p10,(unsigned long long)p90,(unsigned long long)(q3-q1));
    }
    return 0;
}
