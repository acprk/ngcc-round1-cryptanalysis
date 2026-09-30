/* Weaver DFR harness: measures raw decryption noise of the submitted reference code. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "params.h"
#include "indcpa.h"
#include "poly.h"
#include "polyvec.h"
#include "msgenc.h"
#include "symmetric.h"
#include "drng.h"
DRNG_ctx drng_algorithm; /* unused, satisfies kem_cca/KEM files if linked */
extern poly weaver_dbg_mp;
static uint64_t sm_state;
static uint64_t splitmix(void){uint64_t z=(sm_state+=0x9e3779b97f4a7c15ULL);z=(z^(z>>30))*0xbf58476d1ce4e5b9ULL;z=(z^(z>>27))*0x94d049bb133111ebULL;return z^(z>>31);}
static void rnd(uint8_t*b,size_t n){for(size_t i=0;i<n;i++){if(i%8==0){uint64_t x=splitmix();memcpy(b+i,&x,(n-i)<8?(n-i):8);}}}
#define Q WEAVER_Q
#define N WEAVER_N
#define STP D4_STEP_LEN
#define LOWPOS (8*LOW_CODEWORD_BYTES)
#if WEAVER_MODE==1
#define HIPAY 112
#define LOWUSED 26
#elif WEAVER_MODE==3
#define HIPAY 220
#define LOWUSED 60
#else
#define HIPAY 448
#define LOWUSED 113
#endif
static int16_t flipabs(int16_t x){ /* same as flipabs_ex: |(x mod+ HALFQ) - Q/4| */
  int32_t r = ((x % WEAVER_HALFQ)+WEAVER_HALFQ)%WEAVER_HALFQ; r -= Q/4; return r<0?-r:r; }
int main(int argc,char**argv){
  long nkeys=atol(argv[1]), nenc=atol(argv[2]); sm_state=strtoull(argv[3],0,10);
  const char*out=argv[4];
  static long long hist[2*Q+1]; static long long shist[4*Q+1];
  long long hierr=0,hierr_pay=0,loerr=0,nct=0, ct_hi_any_pay=0, ct_lo_ge[8]={0};
  long long hi_per_ct_hist[64]={0}, lo_per_ct_hist[64]={0};
  double sum_ai_aj=0,sum_a=0,sum_a2=0,sum_ei_ej=0,sum_e2=0; long long npairs=0;
  FILE*fo=fopen(out,"w"); FILE*fct=NULL; char buf[512]; snprintf(buf,sizeof buf,"%s.perct",out); fct=fopen(buf,"w");
  uint8_t pk[WEAVER_INDCPA_PUBLICKEYBYTES], sk[WEAVER_INDCPA_SECRETKEYBYTES], ct[WEAVER_INDCPA_BYTES];
  uint8_t coins[2*WEAVER_SYMBYTES], m[WEAVER_INDCPA_MSGBYTES], mo[WEAVER_INDCPA_MSGBYTES], ecoins[WEAVER_SYMBYTES];
  for(long kk=0;kk<nkeys;kk++){
    rnd(coins,sizeof coins); indcpa_keypair_derand(pk,sk,coins);
    uint8_t sb[2*WEAVER_SYMBYTES]; expand_keypair_seeds(sb,coins,WEAVER_SYMBYTES);
    long s2=0; for(int i=0;i<WEAVER_K;i++){poly t; poly_getnoise_eta1(&t,sb+WEAVER_SYMBYTES,(uint8_t)i); for(int j=0;j<N;j++) s2+=t.coeffs[j]*t.coeffs[j];}
    for(long ee=0;ee<nenc;ee++){
      rnd(m,sizeof m); rnd(ecoins,sizeof ecoins);
      indcpa_enc(ct,m,pk,ecoins); indcpa_dec(mo,ct,sk);
      long r2=0; for(int i=0;i<WEAVER_K;i++){poly t; poly_getnoise_eta2(&t,ecoins,(uint8_t)(1+i)); for(int j=0;j<N;j++) r2+=t.coeffs[j]*t.coeffs[j];}
      poly w; poly_frommsg(&w,m);
      int16_t e[N], wp[N]; int hb[N], lb[N]; double se2=0; int maxe=0;
      for(int i=0;i<N;i++){ int x=weaver_dbg_mp.coeffs[i]; x%=Q; if(x<0)x+=Q; wp[i]=x;
        int wi=w.coeffs[i]; hb[i]= wi>=WEAVER_HALFQ; lb[i]= (wi - hb[i]*WEAVER_HALFQ)!=0;
        int d=(x-wi)%Q; if(d<0)d+=Q; if(d>Q/2)d-=Q; e[i]=d; hist[d+Q]++; se2+=d*d; if(abs(d)>maxe)maxe=abs(d);}
      /* high layer hard decision given correct low removal */
      int hc=0,hcp=0; for(int i=0;i<N;i++){ int t=wp[i]-lb[i]*(Q/4); if(t<0)t+=Q; int bit=((((uint32_t)t<<1)+Q/2)/Q)&1; if(bit!=hb[i]){hc++; if(i<HIPAY)hcp++;} }
      /* low layer soft decision */
      int lc=0; for(int i=0;i<LOWPOS;i++){ int s=0,S=0; for(int r=0;r<4;r++){ s+=flipabs(wp[i+r*STP]); S+=abs(e[i+r*STP]); }
        int noisy = s < WEAVER_HALFQ; if(i<LOWUSED){ if(noisy!=lb[i]) lc++; shist[S]++; } }
      for(int i=0;i<N;i++){ double a=abs(e[i]); sum_a+=a; sum_a2+=a*a; sum_e2+=(double)e[i]*e[i]; }
      for(int i=0;i<N;i++){ int j=(i+STP); if(j<N){ sum_ai_aj+=abs(e[i])*(double)abs(e[j]); sum_ei_ej+=(double)e[i]*e[j]; npairs++; } }
      hierr+=hc; hierr_pay+=hcp; loerr+=lc; nct++; if(hcp) ct_hi_any_pay++;
      hi_per_ct_hist[hc<63?hc:63]++; lo_per_ct_hist[lc<63?lc:63]++;
      fprintf(fct,"%ld %ld %.6f %d %d %d\n",s2,r2,se2/N,maxe,hc,lc);
    }
  }
  fprintf(fo,"mode %d q %d n %d k %d nct %lld ncoef %lld\n",WEAVER_MODE,Q,N,WEAVER_K,nct,nct*N);
  fprintf(fo,"hierr %lld hierr_pay %lld ct_hi_any_pay %lld loerr %lld lopos %lld\n",hierr,hierr_pay,ct_hi_any_pay,loerr,nct*LOWUSED);
  double ma=sum_a/(nct*N), va=sum_a2/(nct*N)-ma*ma;
  fprintf(fo,"corr_abs_stride %.6f cov_e_stride_norm %.6f\n",(sum_ai_aj/npairs-ma*ma)/va, (sum_ei_ej/npairs)/(sum_e2/(nct*N)));
  fprintf(fo,"hi_per_ct"); for(int i=0;i<64;i++) fprintf(fo," %lld",hi_per_ct_hist[i]); fprintf(fo,"\n");
  fprintf(fo,"lo_per_ct"); for(int i=0;i<64;i++) fprintf(fo," %lld",lo_per_ct_hist[i]); fprintf(fo,"\n");
  fprintf(fo,"hist"); for(int i=0;i<2*Q+1;i++) if(hist[i]) fprintf(fo," %d:%lld",i-Q,hist[i]); fprintf(fo,"\n");
  fprintf(fo,"shist"); for(int i=0;i<4*Q+1;i++) if(shist[i]) fprintf(fo," %d:%lld",i,shist[i]); fprintf(fo,"\n");
  fclose(fo); fclose(fct); return 0;
}
