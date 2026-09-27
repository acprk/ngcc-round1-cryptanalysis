#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
/* Pull in the reference CPA PKE (static Compress_CT/Decompress_CT, CTXT type,
   and the non-static CPAPKE_Decrypt whose !=0 return IS the KEM decaps oracle,
   ccakem.c:61-62). We never modify the reference source. */
#include "cpapke.c"

static uint8_t skb[RLWE_CPA_SK_LEN], pkb[RLWE_CPA_PK_LEN];
static long QUERIES=0;
static int DELTA_COEF=200;   /* pre-compression c1[0]; decompresses to delta' */

/* oracle: rc(CPAPKE_Decrypt)!=0 for a crafted ct with c1=const, one pilot bit, one probe bit */
static int oracle(int a, int c2a_real, int b, int c2b_real){
    CTXT ct; memset(&ct,0,sizeof ct);
    ct.c1[0]=DELTA_COEF;                 /* constant scalar delta */
    ct.c2[a]=(int16_t)c2a_real;          /* probe */
    ct.c2[b]=(int16_t)c2b_real;          /* pilot */
    uint8_t ctb[RLWE_CPA_CT_LEN]; Compress_CT(ctb,&ct);
    QUERIES++;
    /* KEM decaps returns -1 on ECC detect; the reference decoder OOB-writes on the
       weight-2 case, so a real server either returns nonzero or crashes -> both are the
       "failure" oracle answer. Fork to observe it safely. */
    pid_t p=fork();
    if(p==0){ uint8_t msg[RLWE_MSG_LEN]; int r=CPAPKE_Decrypt(msg,skb,ctb); _exit(r==0?0:1); }
    int st; waitpid(p,&st,0);
    if(WIFSIGNALED(st)) return 1;                 /* crash = failure branch */
    return WEXITSTATUS(st)!=0;                     /* nonzero rc = failure branch */
}
int main(int argc,char**argv){
    int NREC = argc>1?atoi(argv[1]):522;   /* directly-probed coeffs 0..521 (pilot=522) */
    
    /* reference keygen (CPA) */
    CPAPKE_KeyGen(skb,pkb);
    /* recover delta' = decompress(compress(DELTA_COEF)) */
    CTXT probe; memset(&probe,0,sizeof probe); probe.c1[0]=DELTA_COEF;
    uint8_t tb[RLWE_CPA_CT_LEN]; Compress_CT(tb,&probe);
    CTXT back; Decompress_CT(&back,tb);
    int dprime=back.c1[0];
    /* true secret for SCORING ONLY */
    CPASK strue; Decompress_SK(&strue,skb);   /* SK-READ [SCORING] */
    /* stored secret is in Nussbaumer eval domain; bring to coefficient domain for scoring */
    int16_t scoef[RLWE_K*RLWE_N];
    memcpy(scoef,strue.s,sizeof scoef);
    InverseNussbamuer(scoef,scoef);
    PolyMod(scoef,scoef);
    for(int i=0;i<RLWE_K*RLWE_N;i++){ int v=((scoef[i]%RLWE_Q)+RLWE_Q)%RLWE_Q; if(v>RLWE_Q/2)v-=RLWE_Q; scoef[i]=(int16_t)v; }
    int pilot=522, pilot_real=1729;           /* d_b ~ q/2 -> bit1 reliably */
    int q=RLWE_Q, lo_bound=q/4;               /* 864 */
    int t0=clock();
    int correct=0, tested=0;
    int16_t srec[600];
    for(int a=0;a<NREC;a++){
        /* bisect the lower 0->1 transition of the probe bit in real c2 units [0,1728] */
        int lo=0, hi=1728;
        if(!oracle(a,hi,pilot,pilot_real)){ srec[a]=999; continue; } /* window upper below hi (large |s|) */
        while(hi-lo>2){
            int mid=(lo+hi)/2;
            if(oracle(a,mid,pilot,pilot_real)) hi=mid; else lo=mid;
        }
        int edge=(lo+hi)/2;              /* ~ lo_bound + dprime*s_a */
        double sa=(double)(edge-lo_bound)/dprime;
        int sai=(int)(sa<0? sa-0.5 : sa+0.5);
        srec[a]=sai;
        tested++;
        if(sai==scoef[a]) correct++;   /* SK-READ [SCORING] */
    }
    /* second pass: coefficients whose window fell outside [0,1728] have |s|>=5; a smaller
       delta widens the resolvable range. Re-probe only those. */
    int save=DELTA_COEF; DELTA_COEF=120;
    CTXT pr2; memset(&pr2,0,sizeof pr2); pr2.c1[0]=DELTA_COEF;
    uint8_t tb2[RLWE_CPA_CT_LEN]; Compress_CT(tb2,&pr2); CTXT bk2; Decompress_CT(&bk2,tb2); int dp2=bk2.c1[0];
    for(int a=0;a<NREC;a++){
        if(srec[a]!=999) continue;
        int lo=0,hi=2400;                 /* wider real range for larger |s| */
        if(!oracle(a,hi,pilot,pilot_real)){ continue; }
        while(hi-lo>2){ int mid=(lo+hi)/2; if(oracle(a,mid,pilot,pilot_real)) hi=mid; else lo=mid; }
        int edge=(lo+hi)/2; double sa=(double)(edge-lo_bound)/dp2; int sai=(int)(sa<0?sa-0.5:sa+0.5);
        srec[a]=sai; tested++; if(sai==scoef[a]) correct++;
    }
    DELTA_COEF=save;
    double dt=(double)(clock()-t0)/CLOCKS_PER_SEC;
    printf("delta'=%d  probed=%d  correct=%d/%d  queries=%ld  time=%.2fs\n",
           dprime,tested,correct,tested,QUERIES,dt);
    /* show a few */
    printf("first 16 (rec vs true): ");
    for(int a=0;a<16;a++) printf("%d/%d ",srec[a],scoef[a]);
    printf("\n");
    return 0;
}
