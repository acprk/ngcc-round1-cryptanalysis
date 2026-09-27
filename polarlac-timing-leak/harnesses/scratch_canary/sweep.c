/* sweep.c  Fast (no-timing) map of the canary-freedom vs probe-cleanliness trade-off.
   For each fixed partner-flip count nf: search for a canary (R(m0)=4 & R(m1)>=6 or swap),
   report search cost, then run random-target probes and report off-model rate and the
   EXACT-R oracle error (ceiling of any timing oracle). Uses SK only for labeling/scoring. */
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
#define C 32
static int pmod(int a,int m){a%=m;if(a<0)a+=m;return a;}
static int recompute_R(const uint8_t*m){uint8_t din[PKE_MESSAGE_BYTES+PKE_PUBLIC_KEY_BYTES];uint8_t g[KEM_SS_BYTES+KEM_SEED_LEN_BYTES];
 memcpy(din,m,PKE_MESSAGE_BYTES);memcpy(din+PKE_MESSAGE_BYTES,PK,PKE_PUBLIC_KEY_BYTES);
 bit_xof((KEM_SS_BYTES+KEM_SEED_LEN_BYTES)*8ULL,din,sizeof(din)*8ULL,g);const uint8_t*se=g+KEM_SS_BYTES;
 uint8_t n=0;int R=0;int16_t c[RL_KEM_N];for(int p=0;p<4;p++){for(;;){poly_generate_tenary(c,se,n);n++;R++;if(fft_within_bound_int16(c,(int32_t)RL_KEM_T))break;}}return R;}
static void build_ct(uint8_t*ct,int k,int a,const uint8_t*cw){polarlac_polyvec u;memset(&u,0,sizeof(u));u.vec[k].coeffs[a]=(int16_t)C;
 polyvec_byte_compress(ct,&u);uint8_t com[RL_KEM_Lv];for(int i=0;i<RL_KEM_Lv;i++)com[i]=(uint8_t)(cw[i]&7);pack_c2_dbit(ct+C1_LEN_BYTES,com);}
int main(int argc,char**argv){
    int MAXTRY=argc>1?atoi(argv[1]):2000000;
    int NQ=argc>2?atoi(argv[2]):5000;
    uint8_t ds[48];for(int i=0;i<48;i++)ds[i]=(uint8_t)(i*7+1);init_random_number(&drng_algorithm,ds,sizeof(ds));
    kem_keygen(PK,&PKL,SK,&SKL);
    int k=0,a=0; srand(20240930);
    int nfs[]={6,8,10,12,16,20,28}; int NN=sizeof(nfs)/sizeof(nfs[0]);
    printf("nf  canary?  searchcost  R0 R1   off-model%%  exactR-oracle-err%%  (on-model n)\n");
    for(int idx=0;idx<NN;idx++){
        int nf=nfs[idx];
        uint8_t canary[256]; int have=0,R0=0,R1=0; long searched=0;
        uint8_t m0[PKE_MESSAGE_BYTES],m1[PKE_MESSAGE_BYTES];
        for(int t=0;t<MAXTRY && !have;t++){
            uint8_t fl[256];memset(fl,0,sizeof(fl));int c2=0;while(c2<nf){int i=32+rand()%224;if(!fl[i]){fl[i]=1;c2++;}}
            uint8_t cw[RL_KEM_Lv],ct[PKE_CIPHERTEXT_BYTES],a0[PKE_MESSAGE_BYTES],a1[PKE_MESSAGE_BYTES];
            for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(i<32)?0:(fl[i]?4:0);build_ct(ct,k,a,cw);PKE_Decrypt(a0,ct,SK);int r0=recompute_R(a0);
            for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(i<32)?4:(fl[i]?4:0);build_ct(ct,k,a,cw);PKE_Decrypt(a1,ct,SK);int r1=recompute_R(a1);
            searched++;
            if((r0==4&&r1>=6)||(r1==4&&r0>=6)){have=1;memcpy(canary,fl,256);R0=r0;R1=r1;memcpy(m0,a0,16);memcpy(m1,a1,16);}
        }
        if(!have){printf("%2d  NO       >%ld     -  -    -           -\n",nf,searched);continue;}
        int slow4=(R1>=6); /* slow side = grid4 if R1>=6 */
        long on=0,off=0,eerr=0;
        for(int q=0;q<NQ;q++){uint8_t cw[RL_KEM_Lv];for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(i<32)?(uint8_t)(rand()&7):(canary[i]?4:0);
            uint8_t ct[PKE_CIPHERTEXT_BYTES];build_ct(ct,k,a,cw);uint8_t m[PKE_MESSAGE_BYTES];PKE_Decrypt(m,ct,SK);
            int q0=memcmp(m,m0,16)==0,q1=memcmp(m,m1,16)==0;
            if(!q0&&!q1){off++;continue;} on++;
            int gt_slow=slow4?q1:q0; int Rex=recompute_R(m); int pred_slow=(Rex>=6);
            if(pred_slow!=gt_slow)eerr++; }
        fflush(stdout);
        printf("%2d  YES      %ld      %d  %d    %.2f       %.4f            (%ld)\n",
            nf,searched,R0,R1,100.0*off/NQ, on?100.0*eerr/on:0.0, on);
    }
    return 0;
}
