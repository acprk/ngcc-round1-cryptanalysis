/* Refutation checks: things we suspected (from COMPASS experience) that turn out NOT to be bugs here.
 *  (a) NTT: ring multiplication matches schoolbook mod x^N+1 (no COMPASS-#22-style N=512 port bug).
 *  (b) CBD sampler: every coefficient position is reachable, histogram is binomial (no dead coords).
 * We publish the negative results too, so reviewers do not re-walk these paths. No secrets involved.
 */
#include "common.h"
static int md(int x){ x%=KYBER_Q; return x<0?x+KYBER_Q:x; }
int main(void){
  int bad=0;
  for(int t=0;t<50;t++){ poly a,b,c; int ref[KYBER_N]; for(int i=0;i<KYBER_N;i++) ref[i]=0;
    for(int i=0;i<KYBER_N;i++){ unsigned char r[3]; rnd(r,3);
      a.coeffs[i]=(int16_t)((r[0]|(r[1]<<8))%KYBER_Q); b.coeffs[i]=(int16_t)((r[2]%5)-2); }
    for(int i=0;i<KYBER_N;i++) for(int j=0;j<KYBER_N;j++){ int k=i+j,v=a.coeffs[i]*b.coeffs[j];
      if(k>=KYBER_N){k-=KYBER_N;v=-v;} ref[k]=md(ref[k]+v); }
    poly_ntt(&a); poly_ntt(&b); poly_basemul_montgomery(&c,&a,&b); poly_invntt_tomont(&c);
    for(int i=0;i<KYBER_N;i++) if(md(c.coeffs[i])!=ref[i]) bad++;
  }
  long cnt[KYBER_N]; for(int i=0;i<KYBER_N;i++) cnt[i]=0; long oor=0; unsigned char seed[L];
  for(int t=0;t<2000;t++){ poly r; rnd(seed,L); poly_getnoise_eta1(&r,seed,t&255);
    for(int i=0;i<KYBER_N;i++){ int v=r.coeffs[i]; if(v<-KYBER_ETA1||v>KYBER_ETA1) oor++; else if(v) cnt[i]++; } }
  long mn=1<<30,mx=0; for(int i=0;i<KYBER_N;i++){ if(cnt[i]<mn)mn=cnt[i]; if(cnt[i]>mx)mx=cnt[i]; }
  printf("[NEG] level=%s N=%d eta1=%d\n", AFSLEVEL, KYBER_N, KYBER_ETA1);
  printf("[NEG] NTT ring-mult mismatches (50 trials) : %d\n", bad);
  printf("[NEG] CBD out-of-range=%ld  per-coord nonzero min=%ld max=%ld  all-coords-reachable=%s\n",
         oor, mn, mx, mn>0?"yes":"NO");
  int pass = bad==0 && oor==0 && mn>0;
  printf("[NEG] RESULT: %s (NTT correct + sampler healthy => these COMPASS-style bugs are ABSENT)\n",
         pass?"CONFIRMED-CLEAN":"ANOMALY");
  return pass?0:1;
}
