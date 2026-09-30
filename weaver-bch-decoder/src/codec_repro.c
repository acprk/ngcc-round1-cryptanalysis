/* Codec-level repro on author's latest GitHub code (ca99d0f): poly_frommsg -> flip e high-layer
   data coefficients by +(q+1)/2 -> poly_tomsg (the real decaps decoding path). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "msgenc.h"
#if WEAVER_MODE==3
#define ELL1 220
#define TT 4
#else
#define ELL1 448
#define TT 7
#endif
static uint64_t s=0x9E3779B97F4A7C15ULL;
static uint64_t xr(void){s^=s<<13;s^=s>>7;s^=s<<17;return s;}
static void hex(const char*l,const uint8_t*b){printf("%s",l);for(int i=0;i<WEAVER_INDCPA_MSGBYTES;i++)printf("%02x",b[i]);printf("\n");}
static int trial(const uint8_t*m,const int*pos,int e,uint8_t*out){
  poly w; poly_frommsg(&w,m);
  for(int k=0;k<e;k++){int16_t c=w.coeffs[pos[k]]+WEAVER_HALFQ; if(c>=WEAVER_Q)c-=WEAVER_Q; w.coeffs[pos[k]]=c;}
  poly_tomsg(out,&w); return memcmp(out,m,WEAVER_INDCPA_MSGBYTES)!=0;
}
int main(int argc,char**argv){
  uint8_t m[WEAVER_INDCPA_MSGBYTES],out[WEAVER_INDCPA_MSGBYTES]; int pos[16];
  if(argc>1 && !strcmp(argv[1],"replay")){ /* replay <msghex> p1 p2 ... */
    const char*h=argv[2]; for(int i=0;i<WEAVER_INDCPA_MSGBYTES;i++){unsigned v;sscanf(h+2*i,"%2x",&v);m[i]=v;}
    int e=argc-3; for(int k=0;k<e;k++)pos[k]=atoi(argv[3+k]);
    int bad=trial(m,pos,e,out); hex("in : ",m); hex("out: ",out); printf("result: %s\n",bad?"WRONG MESSAGE":"correct"); return 0; }
  int N=argc>1?atoi(argv[1]):20000; int printed=0;
  for(int e=1;e<=TT+1;e++){ int bad=0;
    for(int tr=0;tr<N;tr++){
      for(int i=0;i<WEAVER_INDCPA_MSGBYTES;i++)m[i]=xr();
      int used[ELL1]={0}; for(int k=0;k<e;k++){int p;do p=xr()%ELL1;while(used[p]);used[p]=1;pos[k]=p;}
      /* mode 3: mu_tilde[27] low nibble is zeroed, only 220 msg bits go high -> positions <220 are payload */
      if(trial(m,pos,e,out)){ bad++; if(!printed && e<=TT){ printed=1; printf("FIRST FAILING PATTERN (e=%d <= t=%d):\n",e,TT); hex("  msg: ",m); printf("  flipped high-layer coeffs:"); for(int k=0;k<e;k++)printf(" %d",pos[k]); printf("\n"); hex("  out: ",out);} }
    }
    printf("e=%d high-layer errors: wrong message %d/%d (%.3f%%)\n",e,bad,N,100.0*bad/N);
  }
}
