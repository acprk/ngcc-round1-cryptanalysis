/* Empirical IRS leakage test: fixed secret, many (y,c) -> z_tilde; statistics of <z_tilde, s~ X^j>. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "rounding.h"
#include "irs.h"
#include "symmetric.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
static void fill(uint8_t *b, size_t n, uint64_t *st){ for(size_t i=0;i<n;i++){ *st = *st*6364136223846793005ULL+1442695040888963407ULL; b[i]=(uint8_t)(*st>>56);} }
/* <a, b X^j> in Z[X]/(X^N+1) across KVEC polys */
static double ip_shift(const poly *a, const poly *b, int j){
  double s=0; for(int p=0;p<KVEC;p++) for(int k=0;k<N;k++){ int idx=k+j; int sg=1; if(idx>=N){idx-=N; sg=-1;} s += (double)a[p].coeffs[idx]*sg*b[p].coeffs[k]; } return s; }
int main(int argc,char**argv){
  long T = argc>1? atol(argv[1]) : 20000;
  int mode = argc>2? atoi(argv[2]) : 0; /* 1 = naive z=y+c*s (sanity, should leak) */
  uint64_t st=12345; uint8_t seed[64];
  poly s1s2[ELL+EM], full[KVEC], sk[KVEC];
  for(;;){ fill(seed,64,&st); expand_s(s1s2, seed); memset(&full[0],0,sizeof(poly)); full[0].coeffs[0]=1;
    for(int j=0;j<ELL+EM;j++) full[1+j]=s1s2[j]; stretch_s(sk, full); if(keygen_norm_ok(sk)) break; }
  double V=0; for(int p=0;p<KVEC;p++) for(int k=0;k<N;k++) V+=(double)sk[p].coeffs[k]*sk[p].coeffs[k];
  printf("||s~||=%.2f\n", sqrt(V));
  double m_in=0,m_out=0,q_in=0,q_out=0; long n_in=0,n_out=0;
  double var[KVEC]={0}; 
  for(long t=0;t<T;t++){
    uint8_t sy[SEEDBYTES], sc[CHALLENGESEEDBYTES], irs_seed[1+SEEDBYTES];
    poly y[KVEC], c, z[KVEC]; xof_ctx ctx;
    fill(sy,SEEDBYTES,&st); fill(sc,CHALLENGESEEDBYTES,&st);
    sample_y(y, sy); sample_c(&c, sc);
    if(mode==0){ irs_seed[0]=0x09; memcpy(irs_seed+1,sy,SEEDBYTES); xof256_init(&ctx,irs_seed,1+SEEDBYTES); reject_sample(&ctx, z, y, &c, sk); }
    else { memcpy(z,y,sizeof z); for(int j=0;j<N;j++) if(c.coeffs[j]) for(int p=0;p<KVEC;p++) for(int k=0;k<N;k++){int idx=k+j,sg=1; if(idx>=N){idx-=N;sg=-1;} z[p].coeffs[idx]+=sg*sk[p].coeffs[k];} }
    for(int p=0;p<KVEC;p++) for(int k=0;k<N;k++) var[p]+=(double)z[p].coeffs[k]*z[p].coeffs[k];
    for(int j=0;j<N;j++){ double v=ip_shift(z,sk,j)/V; if(c.coeffs[j]){m_in+=v;q_in+=v*v;n_in++;} else if(j%8==0){m_out+=v;q_out+=v*v;n_out++;} }
  }
  m_in/=n_in; m_out/=n_out; q_in/=n_in; q_out/=n_out;
  printf("T=%ld mode=%d\n",T,mode);
  printf("E[<z,s~X^j>/||s~||^2]  j in supp(c): %.5f (se %.5f)   j notin: %.5f (se %.5f)\n", m_in, sqrt((q_in-m_in*m_in)/n_in), m_out, sqrt((q_out-m_out*m_out)/n_out));
  printf("E[(.)^2]  in: %.4f  out: %.4f   diff %.5f\n", q_in, q_out, q_in-q_out);
  for(int p=0;p<KVEC;p++) printf("std z~[%d]=%.2f\n",p,sqrt(var[p]/T/N));
}
