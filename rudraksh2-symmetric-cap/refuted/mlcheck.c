/* Exhaustively compare the shipped 2D-B2-Minal decoder to a maximum-likelihood
 * (nearest-codeword in the toroidal L2 metric over Z_q^2) decoder, over ALL
 * (x,y) in [0,q)^2. A mismatch inside the guaranteed-decoding region means the
 * shipped decoder is sub-optimal and the true DFR exceeds an ML-based model. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "params.h"
#include "reduce.h"
#include <math.h>
uint16_t minal_b2_code_decode(int16_t target[]);
void     minal_b2_code_encode(int16_t codeword[], uint8_t msg_bits[]);

static int cdist(int a,int b,int q){int d=((a-b)%q+q)%q; if(d>q-d)d=q-d; return d;}

int main(void){
  int q=KEM_Q;
  /* 16 codewords: 4 msg bits -> (c0,c1) via the real encoder */
  int cw[16][2];
  for(int m=0;m<16;m++){ uint8_t b[4]={(m>>3)&1,(m>>2)&1,(m>>1)&1,m&1}; int16_t c[2];
    minal_b2_code_encode(c,b); cw[m][0]=((c[0]%q)+q)%q; cw[m][1]=((c[1]%q)+q)%q; }
  long total=0, mism=0; long mism_by_r[64]={0};
  /* min pairwise codeword distance (packing radius) */
  long dmin=1<<30;
  for(int i=0;i<16;i++)for(int j=0;j<16;j++)if(i!=j){ long dd=(long)cdist(cw[i][0],cw[j][0],q); long ee=cdist(cw[i][1],cw[j][1],q); long d2=dd*dd+ee*ee; if(d2<dmin)dmin=d2; }
  double rpack=0.5*/*half min distance*/ (0); /* report d2min instead */
  for(int x=0;x<q;x++)for(int y=0;y<q;y++){
    int16_t t[2]={(int16_t)x,(int16_t)y};
    int dec=minal_b2_code_decode(t)&0xf;
    /* ML: nearest codeword by toroidal squared distance */
    long best=1<<30, bm=-1;
    for(int m=0;m<16;m++){ long dx=cdist(x,cw[m][0],q), dy=cdist(y,cw[m][1],q); long d2=dx*dx+dy*dy; if(d2<best){best=d2;bm=m;} }
    total++;
    if(dec!=bm){ mism++; long dx=cdist(x,cw[dec][0],q),dy=cdist(y,cw[dec][1],q); long dd2=dx*dx+dy*dy;
      /* how much farther is the shipped choice than ML, as sqrt */
      int extra=(int)(dd2-best); if(extra<0)extra=0; int bucket=(int)(dd2>best? (dd2-best>63?63:dd2-best):0); mism_by_r[bucket>63?63:bucket]++; }
  }
  printf("q=%d  min codeword sq-dist d2min=%ld (packing radius r=%.1f)\n",q,dmin,0.5*/*approx*/  sqrt((double)dmin));
  printf("points=%ld  decoder!=ML: %ld  (%.4f%%)\n",total,mism,100.0*mism/total);
  return 0;
}
