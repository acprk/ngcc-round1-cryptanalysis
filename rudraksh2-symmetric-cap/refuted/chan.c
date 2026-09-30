/* Gaussian-channel decoder-quality sweep: encode a random 4-bit message with the
 * REAL minal encoder, add iid Gaussian noise (stddev sigma) to both coordinates,
 * decode with (a) the shipped decoder and (b) an ML nearest-codeword decoder.
 * Report per-sigma failure rates. shipped/ML >> 1 means the code loses bits vs an
 * optimal-decoder DFR model; ~1 means the shipped decoder is effectively optimal. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include "params.h"
#include "reduce.h"
uint16_t minal_b2_code_decode(int16_t target[]);
void     minal_b2_code_encode(int16_t codeword[], uint8_t msg_bits[]);
static int cdist(int a,int b,int q){int d=((a-b)%q+q)%q; if(d>q-d)d=q-d; return d;}
static double g(void){ double u=(rand()+1.0)/(RAND_MAX+2.0),v=(rand()+1.0)/(RAND_MAX+2.0); return sqrt(-2*log(u))*cos(2*M_PI*v);}
int main(int argc,char**argv){
  int q=KEM_Q; long N=argc>1?atol(argv[1]):2000000; srand(argc>2?atoi(argv[2]):1);
  int cw[16][2]; for(int m=0;m<16;m++){uint8_t b[4]={(m>>3)&1,(m>>2)&1,(m>>1)&1,m&1};int16_t c[2];minal_b2_code_encode(c,b);cw[m][0]=((c[0]%q)+q)%q;cw[m][1]=((c[1]%q)+q)%q;}
  printf("q=%d  N=%ld per sigma\n",q,N);
  printf("sigma   shipped_fail      ML_fail        ratio\n");
  for(double sig=40; sig<=260; sig+=40){
    long fs=0,fm=0;
    for(long i=0;i<N;i++){ int m=rand()&15;
      int x=(int)llround(cw[m][0]+sig*g()); int y=(int)llround(cw[m][1]+sig*g());
      x=((x%q)+q)%q; y=((y%q)+q)%q;
      int16_t t[2]={(int16_t)x,(int16_t)y}; int ds=minal_b2_code_decode(t)&0xf;
      long best=1L<<40,bm=-1; for(int c=0;c<16;c++){long dx=cdist(x,cw[c][0],q),dy=cdist(y,cw[c][1],q),d2=dx*dx+dy*dy; if(d2<best){best=d2;bm=c;}}
      fs+=(ds!=m); fm+=(bm!=m);
    }
    printf("%5.0f   %ld/%ld=2^%.1f  %ld/%ld=2^%.1f  %.2f\n",sig,fs,N,fs?log2((double)fs/N):-99,fm,N,fm?log2((double)fm/N):-99, fm?(double)fs/fm:0);
  }
  return 0;
}
