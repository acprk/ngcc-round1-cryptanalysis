/* Report the support of the linked poly_challenge (spec Alg.6 vs reference).  Public data only. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "params.h"
#include "poly.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
static uint64_t rs=0x243F6A8885A308D3ULL; static uint64_t xr(void){rs^=rs<<13;rs^=rs>>7;rs^=rs<<17;return rs;}
int main(void){
  uint8_t s48[48]; memset(s48,0x11,48); init_random_number(&drng_algorithm,s48,48);
  const int S=20000; static long cnt[/*Nmax*/1024]; long neg=0,tot=0; int badw=0;
  memset(cnt,0,sizeof cnt);
  uint8_t seed[CTILDEBYTES]; poly c;
  for(int t=0;t<S;t++){ for(int i=0;i<CTILDEBYTES;i++) seed[i]=(uint8_t)xr(); poly_challenge(&c,seed);
    int w=0; for(int i=0;i<N;i++){ if(c.coeffs[i]){w++;cnt[i]++;tot++; if(c.coeffs[i]==-1)neg++;} } if(w!=TAU) badw++; }
  int zeros=0; long mx=0; for(int i=0;i<N;i++){ if(!cnt[i]) zeros++; if(cnt[i]>mx) mx=cnt[i]; }
  double chi=0, e=(double)S*TAU/N; for(int i=0;i<N;i++) chi+=(cnt[i]-e)*(cnt[i]-e)/e;
  double lg=TAU; for(int i=0;i<TAU;i++) lg+=log2((double)(N-i)/(i+1));
  printf("N=%d TAU=%d  samples=%d  bad-weight=%d  never-hit=%d/%d  max-freq=%ld/%d  chi2/df=%.1f  frac(-1)=%.4f\n",
         N,TAU,S,badw,zeros,N,mx,S,chi/(N-1),(double)neg/tot);
  printf("challenge space: claimed log2|B_tau.signs| = %.1f bits ; spec-literal min-entropy (fixed support) = %d bits\n",lg,TAU);
  if(zeros>0 && mx==S) printf(">>> FIXED SUPPORT: exactly %d positions used, each in every sample => 2^%d challenges\n",N-zeros,TAU);
  else printf(">>> support looks uniform (this is the reference sampler)\n");
  return 0;
}
