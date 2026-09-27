/* Generic MAMBA-NIKE key-recovery (eta=PARAM_K, n=PARAM_N aware).
 * Same attack as attack.c; joint 4-coord decode with auto scaling+probe design.
 * Only enabled when NCOMB=(2*eta+1)^4 is small enough for the pairwise design. */
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

static uint64_t rng_s;
static uint64_t xnext(void){ rng_s^=rng_s<<13; rng_s^=rng_s>>7; rng_s^=rng_s<<17; return rng_s; }
int nike_randombytes(unsigned char *x, unsigned long long xlen){
  for(unsigned long long i=0;i<xlen;i++) x[i]=(unsigned char)(xnext()>>19); return 0; }
void randombytes(unsigned char *x, unsigned long long xlen){ (void)nike_randombytes(x,xlen); }
static int sgn(int c){ return c>PARAM_Q/2 ? c-PARAM_Q : c; }

#define QQ PARAM_Q
#define ETA PARAM_K
#define LV (2*ETA+1)
#define NG (PARAM_N/4)
static int32_t gfun(int32_t x){ int32_t t=x>>(LOG2Q+2); int32_t c=t&1; t=(t>>1)+c; t*=8*QQ; int32_t d=t-x; return d<0?-d:d; }
static int lddec(int32_t a,int32_t b,int32_t c,int32_t d){ int32_t t=gfun(a)+gfun(b)+gfun(c)+gfun(d)-8*QQ; t>>=31; return t&1; }
static int model_bit(const int s[4],int c0,const int a[4],const int pert[4]){
  int32_t v[4]; for(int m=0;m<4;m++) v[m]=(int32_t)((c0*s[m]+pert[m])&(QQ-1));
  int32_t t0=16*QQ+8*v[0]-QQ*(2*a[0]+a[3]),t1=16*QQ+8*v[1]-QQ*(2*a[1]+a[3]),
          t2=16*QQ+8*v[2]-QQ*(2*a[2]+a[3]),t3=16*QQ+8*v[3]-QQ*a[3];
  return lddec(t0,t1,t2,t3);
}
static int MARGIN=500;
static int robust_bit(const int s[4],int c0,const int a[4]){
  int base=-1;
  for(int mask=0;mask<16;mask++){ int p[4]; for(int m=0;m<4;m++)p[m]=(mask&(1<<m))?MARGIN:-MARGIN;
    int b=model_bit(s,c0,a,p); if(base<0)base=b; else if(b!=base)return 2; }
  int pz[4]={0,0,0,0}; if(model_bit(s,c0,a,pz)!=base) return 2; return base;
}

static int *SCAL; static int NSCAL;
static int NCOMB;
static int (*combo)[4];
static int *probe_c0; static int (*probe_a)[4]; static int NPROBE;
static unsigned char *sigtab; /* NCOMB x NPROBE */
static int scal_idx_of(int c0){ for(int i=0;i<NSCAL;i++)if(SCAL[i]==c0)return i; return 0;}

static void build_probes(void){
  NCOMB=1; for(int i=0;i<4;i++)NCOMB*=LV;
  combo=malloc(sizeof(int[4])*NCOMB);
  int idx=0;
  for(int x0=-ETA;x0<=ETA;x0++)for(int x1=-ETA;x1<=ETA;x1++)for(int x2=-ETA;x2<=ETA;x2++)for(int x3=-ETA;x3<=ETA;x3++){
    combo[idx][0]=x0;combo[idx][1]=x1;combo[idx][2]=x2;combo[idx][3]=x3;idx++;}
  int NPR=NSCAL*256; int *prc0=malloc(sizeof(int)*NPR); int (*pra)[4]=malloc(sizeof(int[4])*NPR); int p=0;
  for(int sc=0;sc<NSCAL;sc++)for(int a0=0;a0<4;a0++)for(int a1=0;a1<4;a1++)for(int a2=0;a2<4;a2++)for(int a3=0;a3<4;a3++){
    prc0[p]=SCAL[sc];pra[p][0]=a0;pra[p][1]=a1;pra[p][2]=a2;pra[p][3]=a3;p++;}
  unsigned char *full=malloc((size_t)NCOMB*NPR);
  for(int c=0;c<NCOMB;c++)for(int q=0;q<NPR;q++) full[(size_t)c*NPR+q]=(unsigned char)robust_bit(combo[c],prc0[q],pra[q]);
  long npairs=(long)NCOMB*(NCOMB-1)/2;
  int *pa=malloc(sizeof(int)*npairs), *pb=malloc(sizeof(int)*npairs);
  if(!pa||!pb){ fprintf(stderr,"NCOMB=%d too large for pair design (%ld pairs)\n",NCOMB,npairs); exit(2);}
  long np=0; for(int a=0;a<NCOMB;a++)for(int b=a+1;b<NCOMB;b++){pa[np]=a;pb[np]=b;np++;}
  char *sep=calloc(npairs,1); long remaining=npairs;
  char *used=calloc(NPR,1);
  probe_c0=malloc(sizeof(int)*NPR); probe_a=malloc(sizeof(int[4])*NPR); NPROBE=0;
  while(remaining>0){
    int bq=-1; long bg=-1;
    for(int q=0;q<NPR;q++){ if(used[q])continue; long gain=0;
      for(long i=0;i<np;i++){ if(sep[i])continue; int a=pa[i],b=pb[i];
        unsigned char x=full[(size_t)a*NPR+q],y=full[(size_t)b*NPR+q];
        if(x!=2&&y!=2&&x!=y)gain++; }
      if(gain>bg){bg=gain;bq=q;} }
    if(bg<=0) break;
    for(long i=0;i<np;i++){ if(sep[i])continue; int a=pa[i],b=pb[i];
      unsigned char x=full[(size_t)a*NPR+bq],y=full[(size_t)b*NPR+bq];
      if(x!=2&&y!=2&&x!=y){sep[i]=1;remaining--;} }
    probe_c0[NPROBE]=prc0[bq]; memcpy(probe_a[NPROBE],pra[bq],sizeof(int)*4); used[bq]=1; NPROBE++;
  }
  sigtab=malloc((size_t)NCOMB*NPROBE);
  for(int c=0;c<NCOMB;c++)for(int k=0;k<NPROBE;k++) sigtab[(size_t)c*NPROBE+k]=(unsigned char)robust_bit(combo[c],probe_c0[k],probe_a[k]);
  fprintf(stderr,"[design] eta=%d n=%d scalings=%d NCOMB=%d probes=%d unsep=%ld\n",ETA,PARAM_N,NSCAL,NCOMB,NPROBE,remaining);
  free(full);free(pa);free(pb);free(sep);free(used);free(prc0);free(pra);
}

int main(int argc,char**argv){
  int nkeys=argc>1?atoi(argv[1]):5;
  /* candidate scalings: c0=1024*t (8*c0 = t*q). choose enough to separate LV levels. */
  int cand[8]={1024,2048,3072,4096,512,1536,2560,3584};
  int nsc=argc>2?atoi(argv[2]):(ETA<=2?3:ETA<=3?4:6);
  SCAL=malloc(sizeof(int)*nsc); NSCAL=nsc; for(int i=0;i<nsc;i++)SCAL[i]=cand[i];
  if(argc>3)MARGIN=atoi(argv[3]);
  build_probes();

  long tot=0; int succ=0; double tt=0;
  for(int key=0;key<nkeys;key++){
    rng_s=0x1000+key*2654435761ULL;
    unsigned char pkB[NIKE_SENDABYTES]; poly sB;
    nike_keygen(pkB,&sB);
    unsigned char mu[NIKE_SEEDBYTES]; for(int i=0;i<NIKE_SEEDBYTES;i++)mu[i]=(unsigned char)xnext();
    poly *uraw=malloc(sizeof(poly)*NSCAL);
    for(int s=0;s<NSCAL;s++){ poly bt,ba; memset(&bt,0,sizeof(bt)); bt.coeffs[0]=(uint16_t)(SCAL[s]&(QQ-1)); a_bp_target_to_uraw(&uraw[s],&ba,&bt,mu); }
    struct timespec t0,t1; clock_gettime(CLOCK_MONOTONIC,&t0);
    unsigned char *obs=malloc((size_t)NPROBE*NG);
    long q=0;
    for(int k=0;k<NPROBE;k++){
      int sidx=scal_idx_of(probe_c0[k]);
      poly c; memset(&c,0,sizeof(c));
      for(int i=0;i<NG;i++){c.coeffs[4*i]=probe_a[k][0];c.coeffs[4*i+1]=probe_a[k][1];c.coeffs[4*i+2]=probe_a[k][2];c.coeffs[4*i+3]=probe_a[k][3];}
      unsigned char m1[NIKE_SENDBBYTES],nu[NIKE_KEYBYTES];
      a_encode_b(m1,mu,&uraw[sidx],&c);
      nike_shareda(nu,&sB,pkB,m1); q++;
      for(int i=0;i<NG;i++)obs[(size_t)k*NG+i]=(nu[i>>3]>>(i&7))&1;
    }
    /* ML decode */
    poly rec_sB; memset(&rec_sB,0,sizeof(rec_sB));
    for(int i=0;i<NG;i++){
      int best=0,bestd=1<<30;
      for(int c=0;c<NCOMB;c++){ int d=0;
        for(int k=0;k<NPROBE;k++){unsigned char s=sigtab[(size_t)c*NPROBE+k]; if(s!=2&&s!=obs[(size_t)k*NG+i])d++;}
        if(d<bestd){bestd=d;best=c;} }
      int coord[4]={i,i+NG,i+2*NG,i+3*NG};
      for(int m=0;m<4;m++){int val=((combo[best][m])%QQ+QQ)%QQ;rec_sB.coeffs[coord[m]]=(uint16_t)val;}
    }
    /* denoise refinement */
    { poly residual,ba,bt; memset(&bt,0,sizeof(bt)); bt.coeffs[0]=1024; a_bp_target_to_uraw(&uraw[0],&ba,&bt,mu); memcpy(&residual,&ba,sizeof(poly)); residual.coeffs[0]=0;
      for(int iter=0;iter<8;iter++){ poly noise; poly_pointwise(&noise,&rec_sB,&residual); int changed=0;
        for(int i=0;i<NG;i++){ int coord[4]={i,i+NG,i+2*NG,i+3*NG}; int npv[4];
          for(int m=0;m<4;m++){int nn=noise.coeffs[coord[m]]; if(nn>QQ/2)nn-=QQ; npv[m]=nn;}
          int best=0,bestd=1<<30;
          for(int c=0;c<NCOMB;c++){int d=0; for(int k=0;k<NPROBE;k++){int pb=model_bit(combo[c],probe_c0[k],probe_a[k],npv); if(pb!=obs[(size_t)k*NG+i])d++;} if(d<bestd){bestd=d;best=c;}}
          for(int m=0;m<4;m++){int val=((combo[best][m])%QQ+QQ)%QQ; if(rec_sB.coeffs[coord[m]]!=(uint16_t)val){rec_sB.coeffs[coord[m]]=(uint16_t)val;changed=1;}}
        }
        if(!changed)break;
      }
    }
    clock_gettime(CLOCK_MONOTONIC,&t1);
    double dt=(t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    int wrong=0; for(int j=0;j<PARAM_N;j++)if(sgn(rec_sB.coeffs[j])!=sgn(sB.coeffs[j]))wrong++;
    int ok=(wrong==0); succ+=ok; tot+=q; tt+=dt;
    printf("key %d: queries=%ld wrong_coeffs=%d %s (%.2fs)\n",key,q,wrong,ok?"FULL RECOVERY":"FAIL",dt);
    free(uraw);free(obs);
  }
  printf("SUMMARY MAMBA-NIKE-%d: %d/%d full recoveries, mean queries=%.1f, mean time=%.2fs\n",NIKE_LEVEL,succ,nkeys,(double)tot/nkeys,tt/nkeys);
  return 0;
}
