/* MAMBA-NIKE key-mismatch / reaction key-recovery against the reference responder.
 *
 * Model: attacker plays initiator, sends crafted M1=(mu,u,h) to the STATIC
 * responder (nike_shareda, holding secret sB) and observes the reconciliation
 * oracle rec(sB*u_hat, h) (exposed byte-for-byte in the reference's own
 * STATISTICAL_TEST build). No FO/CCA wrapper, no input validation.
 *
 * Core identity (verified at runtime): poly_ntt/invntt are NO-OPS and
 * poly_pointwise is negacyclic convolution, so the responder computes
 *      v = sB * bp   (mod X^n+1, mod q),   bp = (u<<H_U) - du(mu).
 * Choosing bp = c0 * X^0 gives v[j] = c0*sB[j] + (sB*residual)[j].
 * With c0 in {1024,2048,3072} and 8*c0 a multiple of q the D4 reconciliation
 * becomes a known discrete function of (sB[j],sB[j+n/4],sB[j+n/2],sB[j+3n/4])
 * and the chosen 2-bit help vector; a fixed 71-probe set is injective and
 * robust to the |noise| <= 500 dither term, recovering all n coefficients.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "params.h"
#include "poly.h"
#include "nike.h"
#include "error_correction.h"
#include "harness.h"

/* ---- seeded PRNG for keygen randomness (victim key) ---- */
static uint64_t rng_s;
static uint64_t xnext(void){ rng_s^=rng_s<<13; rng_s^=rng_s>>7; rng_s^=rng_s<<17; return rng_s; }
int nike_randombytes(unsigned char *x, unsigned long long xlen){
  for(unsigned long long i=0;i<xlen;i++) x[i]=(unsigned char)(xnext()>>19); return 0; }
void randombytes(unsigned char *x, unsigned long long xlen){ (void)nike_randombytes(x,xlen); }
static int sgn(int c){ return c>PARAM_Q/2 ? c-PARAM_Q : c; }

/* ---------- discrete reconciliation model (single group, bit 0) ---------- */
#define QQ PARAM_Q
static int32_t gfun(int32_t x){ int32_t t=x>>(LOG2Q+2); int32_t c=t&1; t=(t>>1)+c; t*=8*QQ; int32_t d=t-x; return d<0?-d:d; }
static int lddec(int32_t a,int32_t b,int32_t c,int32_t d){ int32_t t=gfun(a)+gfun(b)+gfun(c)+gfun(d)-8*QQ; t>>=31; return t&1; }
static int model_bit(const int s[4],int c0,const int a[4],const int pert[4]){
  int32_t v[4]; for(int m=0;m<4;m++) v[m]=(int32_t)((c0*s[m]+pert[m])&(QQ-1));
  int32_t t0=16*QQ+8*v[0]-QQ*(2*a[0]+a[3]);
  int32_t t1=16*QQ+8*v[1]-QQ*(2*a[1]+a[3]);
  int32_t t2=16*QQ+8*v[2]-QQ*(2*a[2]+a[3]);
  int32_t t3=16*QQ+8*v[3]-QQ*a[3];
  return lddec(t0,t1,t2,t3);
}
#define MARGIN 500
static int robust_bit(const int s[4],int c0,const int a[4]){
  int base=-1;
  for(int mask=0;mask<16;mask++){ int p[4]; for(int m=0;m<4;m++)p[m]=(mask&(1<<m))?MARGIN:-MARGIN;
    int b=model_bit(s,c0,a,p); if(base<0)base=b; else if(b!=base)return 2; }
  int pz[4]={0,0,0,0}; if(model_bit(s,c0,a,pz)!=base) return 2; return base;
}

/* ---------- probe set design (deterministic greedy, same as d4) ---------- */
static int SCAL[3]={1024,2048,3072};
static int PRc0[768], PRa[768][4], NPR;
static int probe_c0[128], probe_a[128][4], NPROBE;
static unsigned char sigtab[625][128]; /* per-combo signature over chosen probes */
static int combo[625][4];

static void build_probes(void){
  int idx=0;
  for(int x0=-2;x0<=2;x0++)for(int x1=-2;x1<=2;x1++)for(int x2=-2;x2<=2;x2++)for(int x3=-2;x3<=2;x3++){
    combo[idx][0]=x0;combo[idx][1]=x1;combo[idx][2]=x2;combo[idx][3]=x3;idx++;}
  NPR=0;
  for(int sc=0;sc<3;sc++)for(int a0=0;a0<4;a0++)for(int a1=0;a1<4;a1++)for(int a2=0;a2<4;a2++)for(int a3=0;a3<4;a3++){
    PRc0[NPR]=SCAL[sc];PRa[NPR][0]=a0;PRa[NPR][1]=a1;PRa[NPR][2]=a2;PRa[NPR][3]=a3;NPR++;}
  static unsigned char full[625][768];
  for(int c=0;c<625;c++)for(int q=0;q<NPR;q++) full[c][q]=(unsigned char)robust_bit(combo[c],PRc0[q],PRa[q]);
  /* greedy set cover over unseparated pairs */
  static int pa[625*625/2],pb[625*625/2]; int np=0;
  for(int a=0;a<625;a++)for(int b=a+1;b<625;b++){pa[np]=a;pb[np]=b;np++;}
  static char sep[625*625/2]; memset(sep,0,np); int remaining=np;
  char used[768]={0}; NPROBE=0;
  while(remaining>0 && NPROBE<128){
    int bq=-1,bg=-1;
    for(int q=0;q<NPR;q++){ if(used[q])continue; int gain=0;
      for(int i=0;i<np;i++){ if(sep[i])continue; int a=pa[i],b=pb[i];
        if(full[a][q]!=2&&full[b][q]!=2&&full[a][q]!=full[b][q])gain++; }
      if(gain>bg){bg=gain;bq=q;} }
    if(bg<=0) break;
    for(int i=0;i<np;i++){ if(sep[i])continue; int a=pa[i],b=pb[i];
      if(full[a][bq]!=2&&full[b][bq]!=2&&full[a][bq]!=full[b][bq]){sep[i]=1;remaining--;} }
    probe_c0[NPROBE]=PRc0[bq]; memcpy(probe_a[NPROBE],PRa[bq],sizeof(int)*4); used[bq]=1; NPROBE++;
  }
  for(int c=0;c<625;c++)for(int k=0;k<NPROBE;k++) sigtab[c][k]=(unsigned char)robust_bit(combo[c],probe_c0[k],probe_a[k]);
  fprintf(stderr,"[probe design] %d probes, %d unseparated pairs remaining\n",NPROBE,remaining);
}

/* precomputed u_raw for a given (mu,c0): bp=c0*X^0 */
static void make_uraw(poly *uraw, int c0, const unsigned char *mu){
  poly bt,ba; memset(&bt,0,sizeof(bt)); bt.coeffs[0]=(uint16_t)(c0&(PARAM_Q-1));
  a_bp_target_to_uraw(uraw,&ba,&bt,mu);
}

int main(int argc,char**argv){
  int nkeys = argc>1?atoi(argv[1]):5;
  build_probes();

  /* group active pattern used for silencer/strict-oracle analysis: cache uraw per c0 */
  long tot_queries=0; int successes=0; double t_total=0;

  for(int key=0; key<nkeys; key++){
    rng_s = 0x1000+key*2654435761ULL;
    unsigned char pkB[NIKE_SENDABYTES]; poly sB;
    if(nike_keygen(pkB,&sB)!=0){printf("keygen fail\n");return 1;}
    unsigned char mu[NIKE_SEEDBYTES];
    for(int i=0;i<NIKE_SEEDBYTES;i++) mu[i]=(unsigned char)(xnext());
    poly uraw[3];
    for(int s=0;s<3;s++) make_uraw(&uraw[s],SCAL[s],mu);

    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    /* observed bit per (probe,group) */
    static unsigned char obs[128][256];
    long qcount=0;
    for(int k=0;k<NPROBE;k++){
      int sidx = (probe_c0[k]==1024)?0:(probe_c0[k]==2048)?1:2;
      poly c; memset(&c,0,sizeof(c));
      for(int i=0;i<256;i++){ c.coeffs[4*i]=probe_a[k][0];c.coeffs[4*i+1]=probe_a[k][1];
                              c.coeffs[4*i+2]=probe_a[k][2];c.coeffs[4*i+3]=probe_a[k][3]; }
      unsigned char m1[NIKE_SENDBBYTES], nu[32];
      a_encode_b(m1,mu,&uraw[sidx],&c);
      nike_shareda(nu,&sB,pkB,m1);       /* THE ORACLE (reaction/mismatch) */
      qcount++;
      for(int i=0;i<256;i++) obs[k][i]=(nu[i>>3]>>(i&7))&1;
    }
    /* DEBUG: how often does the oracle bit deviate from the true combo's robust prediction? */
    if(getenv("DBG") && key==0){
      int mism=0, wildhit=0; int nwtot=0;
      for(int i=0;i<256;i++){
        int st[4]={sgn(sB.coeffs[i]),sgn(sB.coeffs[i+256]),sgn(sB.coeffs[i+512]),sgn(sB.coeffs[i+768])};
        /* find combo index */
        for(int k=0;k<NPROBE;k++){
          int b=robust_bit(st,probe_c0[k],probe_a[k]);
          if(b==2){ wildhit++; continue; } nwtot++;
          if(b!=obs[k][i]) mism++;
        }
      }
      fprintf(stderr,"[dbg key0] nonwild=%d mismatches=%d wildcards=%d\n",nwtot,mism,wildhit);
    }
    /* decode each group */
    poly rec_sB; memset(&rec_sB,0,sizeof(rec_sB));
    int decoded_groups=0, ambiguous=0;
    for(int i=0;i<256;i++){
      int best=-1, bestd=1<<30, second=1<<30;
      for(int c=0;c<625;c++){
        int d=0;
        for(int k=0;k<NPROBE;k++){ if(sigtab[c][k]!=2 && sigtab[c][k]!=obs[k][i]) d++; }
        if(d<bestd){second=bestd;bestd=d;best=c;} else if(d<second) second=d;
      }
      if(second>bestd) decoded_groups++; else ambiguous++; /* unique ML winner */
      int coord[4]={i,i+256,i+512,i+768};
      for(int m=0;m<4;m++){ int val=((combo[best][m])%PARAM_Q+PARAM_Q)%PARAM_Q; rec_sB.coeffs[coord[m]]=(uint16_t)val; }
    }
    /* ---- denoising refinement: exact noise = sB_est * residual (no extra queries) ---- */
    {
      /* residual = bp(c0=1024) with spike removed (positions !=0); same for all scalings */
      poly residual; memcpy(&residual,&uraw[0],sizeof(poly)); /* placeholder */
      poly bp1024; { poly bt,ba; memset(&bt,0,sizeof(bt)); bt.coeffs[0]=1024; a_bp_target_to_uraw(&uraw[0],&ba,&bt,mu); memcpy(&residual,&ba,sizeof(poly)); }
      residual.coeffs[0]=0; /* remove spike -> pure residual */
      for(int iter=0; iter<6; iter++){
        poly noise; poly_pointwise(&noise,&rec_sB,&residual); /* mod q */
        int changed=0;
        for(int i=0;i<256;i++){
          int coord[4]={i,i+256,i+512,i+768};
          int npv[4]; for(int m=0;m<4;m++){ int nn=noise.coeffs[coord[m]]; if(nn>PARAM_Q/2)nn-=PARAM_Q; npv[m]=nn; }
          int best=-1,bestd=1<<30,second=1<<30;
          for(int c=0;c<625;c++){
            int d=0;
            for(int k=0;k<NPROBE;k++){
              int pb=model_bit(combo[c],probe_c0[k],probe_a[k],npv); /* EXACT noise */
              if(pb!=obs[k][i]) d++;
            }
            if(d<bestd){second=bestd;bestd=d;best=c;} else if(d<second)second=d;
          }
          for(int m=0;m<4;m++){ int val=((combo[best][m])%PARAM_Q+PARAM_Q)%PARAM_Q;
            if(rec_sB.coeffs[coord[m]]!=(uint16_t)val){rec_sB.coeffs[coord[m]]=(uint16_t)val;changed=1;} }
        }
        if(!changed) break;
      }
    }
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double dt=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    /* compare to truth */
    int wrong=0;
    for(int j=0;j<PARAM_N;j++){ if(sgn(rec_sB.coeffs[j])!=sgn(sB.coeffs[j])) wrong++; }
    int ok = (wrong==0);
    successes += ok?1:0; tot_queries += qcount; t_total += dt;
    printf("key %d: queries=%ld decoded_groups=%d ambiguous=%d wrong_coeffs=%d %s (%.3fs)\n",
           key,qcount,decoded_groups,ambiguous,wrong, ok?"FULL RECOVERY":"FAIL", dt);
  }
  printf("\nSUMMARY %s-%d: %d/%d full recoveries, mean queries=%.1f, mean time=%.3fs, oracle=raw-reconciliation(reaction)\n",
         "MAMBA-NIKE",NIKE_LEVEL,successes,nkeys,(double)tot_queries/nkeys,t_total/nkeys);
  return 0;
}
