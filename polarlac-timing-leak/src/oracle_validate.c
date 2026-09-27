/* Phase 1: validate the PolarLAC-Light decapsulation-timing PC-oracle on a pinned core.
   Re-encryption sampler loops until a spectral bound passes; total iteration count R
   depends only on the decrypted message m'. Decaps time is ~affine in R. We measure:
     [1] range of R over honest ciphertexts (ground truth via g_reject_iters);
     [2] cycles-vs-R: class separation and cycles per extra rejection iteration;
     [3] within-class timing noise on the pinned core;
     [4] error rate of the equality oracle "R(ct_a) == R(ct_b)?" from timing alone,
         as a function of the number of repeats per measurement.                       */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <x86intrin.h>
#include "params.h"
#include "KEM_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;
extern unsigned long long g_reject_iters;

static int cmpu(const void*a,const void*b){uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b;return x<y?-1:x>y;}

static uint64_t tdec_min(uint8_t*sk,unsigned long long skl,uint8_t*ct,unsigned long long ctl,uint8_t*ss,int rep){
  unsigned long long l; uint64_t best=~0ULL; unsigned aux;
  for(int r=0;r<rep;r++){ uint64_t a=__rdtscp(&aux); kem_dec(sk,skl,ct,ctl,ss,&l); uint64_t b=__rdtscp(&aux); if(b-a<best)best=b-a; }
  return best;
}
static unsigned true_R(uint8_t*sk,unsigned long long skl,uint8_t*ct,unsigned long long ctl,uint8_t*ss){
  unsigned long long l; g_reject_iters=0; kem_dec(sk,skl,ct,ctl,ss,&l); return (unsigned)g_reject_iters;
}

#define MAXT 6000
static uint8_t cts[MAXT][PKE_CIPHERTEXT_BYTES];
static uint64_t cyc[MAXT]; static unsigned Rv[MAXT];

int main(int argc,char**argv){
  int rep = argc>1?atoi(argv[1]):9;
  int T   = argc>2?atoi(argv[2]):3000; if(T>MAXT)T=MAXT;
  uint8_t seed[64]={0x5a}; init_random_number(&drng_algorithm,seed,64);
  static uint8_t pk[20000],sk[40000],ct[20000],ss[128],ss2[128]; unsigned long long pkl,skl,ctl,ssl;
  kem_keygen(pk,&pkl,sk,&skl);
  for(int i=0;i<300;i++){ kem_enc(pk,pkl,ss,&ssl,ct,&ctl); tdec_min(sk,skl,ct,ctl,ss2,3);} /* warm */

  unsigned Rmin=~0u,Rmax=0;
  for(int i=0;i<T;i++){
    kem_enc(pk,pkl,ss,&ssl,ct,&ctl); memcpy(cts[i],ct,ctl);
    Rv[i]=true_R(sk,skl,ct,ctl,ss2);
    cyc[i]=tdec_min(sk,skl,ct,ctl,ss2,rep);
    if(Rv[i]<Rmin)Rmin=Rv[i]; if(Rv[i]>Rmax)Rmax=Rv[i];
  }
  printf("[1] honest R in [%u,%u]  (ciphertexts=%d, min-of-%d cycles)\n",Rmin,Rmax,T,rep);

  printf("[2/3]  R :  n   median   iqr(=p75-p25)\n");
  double mx=0,my=0; int nb=0;
  for(unsigned r=Rmin;r<=Rmax;r++){ static uint64_t buf[MAXT]; int n=0;
    for(int i=0;i<T;i++) if(Rv[i]==r) buf[n++]=cyc[i];
    if(n<5) continue; qsort(buf,n,8,cmpu);
    printf("      %3u : %-4d %-8llu %llu\n",r,n,(unsigned long long)buf[n/2],(unsigned long long)(buf[n*3/4]-buf[n/4]));
    mx+=r;my+=buf[n/2];nb++;
  }
  mx/=nb;my/=nb; double sn=0,sd=0;
  for(unsigned r=Rmin;r<=Rmax;r++){ static uint64_t buf[MAXT]; int n=0;
    for(int i=0;i<T;i++) if(Rv[i]==r) buf[n++]=cyc[i]; if(n<5)continue; qsort(buf,n,8,cmpu);
    double y=buf[n/2]; sn+=(r-mx)*(y-my); sd+=(r-mx)*(r-mx);}
  double slope=sd>0?sn/sd:0;
  printf("[2] cycles per extra rejection iteration ~ %.0f\n",slope);

  /* [4] equality-oracle error vs repeats. Oracle(ct_a,ct_b): decide R_a==R_b by
     |cyc_a-cyc_b| < slope/2. Sample random pairs; ground truth from Rv. */
  int reps[]={1,3,5,7,9,13,21}; int nr=sizeof(reps)/sizeof(int);
  srand(12345);
  printf("[4] equality-oracle error rate (10000 random ct pairs):\n     rep : err_same  err_diff  overall\n");
  for(int ri=0;ri<nr;ri++){ int rp=reps[ri];
    int NS=0,ND=0,es=0,ed=0;
    for(int q=0;q<10000;q++){
      int a=rand()%T,b=rand()%T; if(a==b)continue;
      uint64_t ca=tdec_min(sk,skl,cts[a],ctl,ss2,rp);
      uint64_t cb=tdec_min(sk,skl,cts[b],ctl,ss2,rp);
      int decide_same = ( (ca>cb?ca-cb:cb-ca) < (uint64_t)(slope/2) );
      int truth_same  = (Rv[a]==Rv[b]);
      if(truth_same){NS++; if(!decide_same)es++;} else {ND++; if(decide_same)ed++;}
    }
    printf("     %3d : %.4f    %.4f    %.4f\n",rp,
      NS?(double)es/NS:0, ND?(double)ed/ND:0, (double)(es+ed)/(NS+ND));
  }
  return 0;
}
