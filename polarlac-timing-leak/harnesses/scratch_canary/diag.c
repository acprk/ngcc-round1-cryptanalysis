/* diag.c  Diagnose the probe 2-outcome structure and canary freedom vs probe-cleanliness. */
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
static int16_t STRUE[RL_KEM_K][RL_KEM_N];
#define C 32
static int pmod(int a,int m){a%=m;if(a<0)a+=m;return a;}
static int grid_val(int w){return (int)(((((uint32_t)w*RL_KEM_Q))+(1u<<(D_C2_BITS-1)))>>D_C2_BITS);}
static int recompute_R(const uint8_t*m){uint8_t din[PKE_MESSAGE_BYTES+PKE_PUBLIC_KEY_BYTES];uint8_t g[KEM_SS_BYTES+KEM_SEED_LEN_BYTES];
 memcpy(din,m,PKE_MESSAGE_BYTES);memcpy(din+PKE_MESSAGE_BYTES,PK,PKE_PUBLIC_KEY_BYTES);
 bit_xof((KEM_SS_BYTES+KEM_SEED_LEN_BYTES)*8ULL,din,sizeof(din)*8ULL,g);const uint8_t*se=g+KEM_SS_BYTES;
 uint8_t n=0;int R=0;int16_t c[RL_KEM_N];for(int p=0;p<4;p++){for(;;){poly_generate_tenary(c,se,n);n++;R++;if(fft_within_bound_int16(c,(int32_t)RL_KEM_T))break;}}return R;}
static void build_ct(uint8_t*ct,int k,int a,const uint8_t*cw){polarlac_polyvec u;memset(&u,0,sizeof(u));u.vec[k].coeffs[a]=(int16_t)C;
 polyvec_byte_compress(ct,&u);uint8_t com[RL_KEM_Lv];for(int i=0;i<RL_KEM_Lv;i++)com[i]=(uint8_t)(cw[i]&7);pack_c2_dbit(ct+C1_LEN_BYTES,com);}
static int popdiff(const uint8_t*a,const uint8_t*b){int d=0;for(int i=0;i<PKE_MESSAGE_BYTES;i++){uint8_t x=a[i]^b[i];while(x){d+=x&1;x>>=1;}}return d;}
int main(int argc,char**argv){
    int NFLIP=argc>1?atoi(argv[1]):0; /* number of partner channels to flip to grid4 */
    int NQ=argc>2?atoi(argv[2]):3000;
    uint8_t ds[48];for(int i=0;i<48;i++)ds[i]=(uint8_t)(i*7+1);init_random_number(&drng_algorithm,ds,sizeof(ds));
    kem_keygen(PK,&PKL,SK,&SKL);
    {const int16_t*sn=(const int16_t*)SK;for(int k=0;k<RL_KEM_K;k++){int16_t t[RL_KEM_N];for(int i=0;i<RL_KEM_N;i++)t[i]=sn[k*RL_KEM_N+i];mq_poly_intt(t);
      for(int i=0;i<RL_KEM_N;i++){int v=pmod(t[i],RL_KEM_Q);if(v>RL_KEM_Q/2)v-=RL_KEM_Q;STRUE[k][i]=(int16_t)v;}}}
    int k=0,a=0;
    srand(777);
    /* choose NFLIP partner channels to flip to grid4 */
    uint8_t fl[256];memset(fl,0,sizeof(fl));int done=0;while(done<NFLIP){int i=32+rand()%224;if(!fl[i]){fl[i]=1;done++;}}
    /* forced extremes */
    uint8_t cw[RL_KEM_Lv],ct[PKE_CIPHERTEXT_BYTES],m0[PKE_MESSAGE_BYTES],m1[PKE_MESSAGE_BYTES];
    for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(i<32)?0:(fl[i]?4:0); build_ct(ct,k,a,cw);PKE_Decrypt(m0,ct,SK);int R0=recompute_R(m0);
    for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(i<32)?4:(fl[i]?4:0); build_ct(ct,k,a,cw);PKE_Decrypt(m1,ct,SK);int R1=recompute_R(m1);
    printf("[diag NFLIP=%d] forced m0(tg0) R=%d, m1(tg4) R=%d, hamming(m0,m1)=%d bits\n",NFLIP,R0,R1,popdiff(m0,m1));
    /* random target probe: how often is m in {m0,m1}? */
    long on=0,off=0,e0=0,e1=0;
    for(int q=0;q<NQ;q++){for(int i=0;i<RL_KEM_Lv;i++)cw[i]=(i<32)?(uint8_t)(rand()&7):(fl[i]?4:0);
        build_ct(ct,k,a,cw);uint8_t m[PKE_MESSAGE_BYTES];PKE_Decrypt(m,ct,SK);
        int q0=memcmp(m,m0,PKE_MESSAGE_BYTES)==0,q1=memcmp(m,m1,PKE_MESSAGE_BYTES)==0;
        if(q0)e0++;else if(q1)e1++;else off++; if(q0||q1)on++;}
    printf("[diag NFLIP=%d] random-target probe: on-model=%ld/%d (m0=%ld m1=%ld) off-model=%ld (%.2f%%)\n",
        NFLIP,on,NQ,e0,e1,off,100.0*off/NQ);
    return 0;
}
