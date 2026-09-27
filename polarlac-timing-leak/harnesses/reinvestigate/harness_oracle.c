/* harness_oracle.c  Faithful REAL-TIMING plaintext-checking oracle test for PolarLAC-Light.
   The oracle the recovery needs is: "does the decrypted message differ from a
   fixed baseline M_BASE (a 1-bit message flip)?"  A timing realization must decide
   this from decapsulation time ALONE (no memcmp on the plaintext).

   Decap time reveals only the FO re-encryption rejection count R = R(m) = a
   pseudorandom function of the decrypted message via H(m||pk). So the timing oracle
   is:  flip? := ( R_est(measured decap time) != R(M_BASE_known_offline) ).

   We measure this oracle's per-query error against ground truth (memcmp used ONLY to
   score, never fed to the oracle) in two regimes:
     (1) naive baseline (M_BASE from the all-zero codeword, as the shipped attack uses)
     (2) engineered slow-canary baseline (M_BASE searched offline to have large R).
   All ciphertexts here use u=0 so the decrypted message = Decode_m(chosen c2), fully
   attacker-known; this isolates the oracle mechanism cleanly. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include "params.h"
#include "KEM_AlgorithmInstance.h"
#include "pke.h"
#include "poly.h"
#include "sample.h"
#include "fft.h"
#include "symmetric.h"

DRNG_ctx drng_algorithm;
static uint8_t PK[PKE_PUBLIC_KEY_BYTES+64], SK[KEM_SK_BYTES+64];
static unsigned long long PKL,SKL;

static inline uint64_t rdtscp(void){unsigned lo,hi,aux;__asm__ __volatile__("rdtscp":"=a"(lo),"=d"(hi),"=c"(aux));return((uint64_t)hi<<32)|lo;}
static inline void lfence(void){__asm__ __volatile__("lfence":::"memory");}

static int recompute_R(const uint8_t *m){
    uint8_t din[PKE_MESSAGE_BYTES+PKE_PUBLIC_KEY_BYTES];
    uint8_t gout[KEM_SS_BYTES+KEM_SEED_LEN_BYTES];
    memcpy(din,m,PKE_MESSAGE_BYTES); memcpy(din+PKE_MESSAGE_BYTES,PK,PKE_PUBLIC_KEY_BYTES);
    bit_xof((KEM_SS_BYTES+KEM_SEED_LEN_BYTES)*8ULL,din,sizeof(din)*8ULL,gout);
    const uint8_t*se=gout+KEM_SS_BYTES; uint8_t nonce=0; int R=0; int16_t cand[RL_KEM_N];
    for(int p=0;p<4;p++){for(;;){poly_generate_tenary(cand,se,nonce);nonce++;R++;if(fft_within_bound_int16(cand,(int32_t)RL_KEM_T))break;}}
    return R;
}
/* build a ciphertext with u=0 and given c2 codeword (grid codes 0..7 per coeff) */
static void build_ct_u0(uint8_t*ct,const uint8_t*cw){
    polarlac_polyvec u; memset(&u,0,sizeof(u));
    polyvec_byte_compress(ct,&u);
    uint8_t com[RL_KEM_Lv]; for(int i=0;i<RL_KEM_Lv;i++)com[i]=(uint8_t)(cw[i]&7);
    pack_c2_dbit(ct+C1_LEN_BYTES,com);
}
static void decrypt_msg(uint8_t*m,const uint8_t*ct){ PKE_Decrypt(m,ct,SK); }

static uint64_t time_dec_mink(const uint8_t*ct,int k){
    uint8_t ss[64];unsigned long long sl;uint64_t best=~0ULL;
    for(int i=0;i<k;i++){lfence();uint64_t t0=rdtscp();lfence();kem_dec(SK,SKL,(uint8_t*)ct,PKE_CIPHERTEXT_BYTES,ss,&sl);lfence();uint64_t t1=rdtscp();lfence();uint64_t d=t1-t0;if(d<best)best=d;}
    return best;
}
/* thresholds auto-calibrated at runtime (see main) */
static uint64_t T45=162000,T56=171000,T67=182000;
static int R_est_from_cyc(uint64_t c){
    if(c<T45)return 4; if(c<T56)return 5; if(c<T67)return 6; return 7;
}
static int cmp_u64(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return(x>y)-(x<y);}

int main(int argc,char**argv){
    int NQ  = argc>1?atoi(argv[1]):3000;   /* queries per regime */
    int MINK= argc>2?atoi(argv[2]):15;
    uint8_t ds[48];for(int i=0;i<48;i++)ds[i]=(uint8_t)(i*7+1);
    init_random_number(&drng_algorithm,ds,sizeof(ds));
    if(kem_keygen(PK,&PKL,SK,&SKL)!=0){fprintf(stderr,"keygen fail\n");return 1;}
    /* warmup */
    {uint8_t cw[RL_KEM_Lv];memset(cw,0,sizeof(cw));uint8_t ct[PKE_CIPHERTEXT_BYTES];build_ct_u0(ct,cw);
     for(int w=0;w<3000;w++)time_dec_mink(ct,3);}

    /* ---- auto-calibrate thresholds: collect min-of-k cycles bucketed by true R ---- */
    {enum{RM=9}; uint64_t *cb[RM]; long cc[RM]={0}; for(int r=0;r<RM;r++)cb[r]=malloc(sizeof(uint64_t)*20000);
     for(int t=0;t<12000;t++){uint8_t cw[RL_KEM_Lv];for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(uint8_t)(rand()&7);
        uint8_t ct[PKE_CIPHERTEXT_BYTES];build_ct_u0(ct,cw);uint8_t m[PKE_MESSAGE_BYTES];decrypt_msg(m,ct);
        int Rt=recompute_R(m); if(Rt>=RM)Rt=RM-1; uint64_t c=time_dec_mink(ct,MINK); cb[Rt][cc[Rt]++]=c;}
     uint64_t med[RM]; for(int r=0;r<RM;r++){if(cc[r]){qsort(cb[r],cc[r],sizeof(uint64_t),cmp_u64);med[r]=cb[r][cc[r]/2];}else med[r]=0;}
     printf("[calib] min-of-%d medians: R4=%llu(n=%ld) R5=%llu(n=%ld) R6=%llu(n=%ld)\n",MINK,
        (unsigned long long)med[4],cc[4],(unsigned long long)med[5],cc[5],(unsigned long long)med[6],cc[6]);
     if(med[4]&&med[5]){T45=(med[4]+med[5])/2;}
     if(med[5]&&med[6]){T56=(med[5]+med[6])/2;} else if(med[4]&&med[5]){T56=med[5]+(med[5]-med[4]);}
     T67=T56+(T56-T45);
     printf("[calib] thresholds T45=%llu T56=%llu T67=%llu\n",(unsigned long long)T45,(unsigned long long)T56,(unsigned long long)T67);
     /* verify classifier */
     int nc=0,ce=0;
     for(int r=4;r<7;r++)for(long i=0;i<cc[r];i++){nc++; if(R_est_from_cyc(cb[r][i])!=r)ce++;}
     printf("[calib] timing R-classifier error (min-of-%d): %d/%d = %.4f%%\n",MINK,ce,nc,100.0*ce/nc);
     for(int r=0;r<RM;r++)free(cb[r]);}

    /* find baselines with target R by varying codeword (u=0, message attacker-known) */
    uint8_t base_naive[PKE_MESSAGE_BYTES], base_r5[PKE_MESSAGE_BYTES], base_r6[PKE_MESSAGE_BYTES];
    int haveR5=0,haveR6=0,Rn;
    {uint8_t cw[RL_KEM_Lv];memset(cw,0,sizeof(cw));uint8_t ct[PKE_CIPHERTEXT_BYTES];build_ct_u0(ct,cw);
     decrypt_msg(base_naive,ct);Rn=recompute_R(base_naive);}
    {long tries=0;while((!haveR5||!haveR6)&&tries<2000000){tries++;uint8_t cw[RL_KEM_Lv];
        for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(uint8_t)(rand()&7);uint8_t ct[PKE_CIPHERTEXT_BYTES];build_ct_u0(ct,cw);
        uint8_t m[PKE_MESSAGE_BYTES];decrypt_msg(m,ct);int R=recompute_R(m);
        if(R==5&&!haveR5){memcpy(base_r5,m,PKE_MESSAGE_BYTES);haveR5=1;}
        if(R>=6&&!haveR6){memcpy(base_r6,m,PKE_MESSAGE_BYTES);haveR6=1;}}
     printf("[baseline] naive R=%d ; found slow-canary R5=%d R6=%d (search ok)\n",Rn,haveR5,haveR6);}

    /* regime tester: given baseline message + its R, run NQ random-message queries,
       ground-truth flip = (m != base), timing-oracle flip = (R_est != Rbase). */
    struct { const char*name; uint8_t*base; } regs[3] = {
        {"naive(R=4)",base_naive},{"canary(R=5)",base_r5},{"canary(R>=6)",base_r6}};
    int Rbase[3]={Rn, haveR5?recompute_R(base_r5):-1, haveR6?recompute_R(base_r6):-1};
    for(int rg=0;rg<3;rg++){
        if(regs[rg].base==NULL||Rbase[rg]<0){continue;}
        long fp=0,fn=0,tp=0,tn=0, flips=0;
        for(int q=0;q<NQ;q++){
            uint8_t cw[RL_KEM_Lv];for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(uint8_t)(rand()&7);
            uint8_t ct[PKE_CIPHERTEXT_BYTES];build_ct_u0(ct,cw);
            uint8_t m[PKE_MESSAGE_BYTES];decrypt_msg(m,ct);
            int gt_flip = memcmp(m,regs[rg].base,PKE_MESSAGE_BYTES)!=0; /* SCORING ONLY */
            uint64_t c=time_dec_mink(ct,MINK);
            int or_flip = (R_est_from_cyc(c)!=Rbase[rg]);
            if(gt_flip)flips++;
            if(gt_flip&&or_flip)tp++; else if(gt_flip&&!or_flip)fn++;
            else if(!gt_flip&&or_flip)fp++; else tn++;
        }
        double err=100.0*(fp+fn)/NQ;
        printf("[%s] Rbase=%d  err=%.3f%%  (FN=%ld FP=%ld TP=%ld TN=%ld ; true-flips=%ld/%d)\n",
            regs[rg].name,Rbase[rg],err,fn,fp,tp,tn,flips,NQ);
    }
    return 0;
}
