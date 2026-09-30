#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "sample.h"
static uint64_t st;
static uint8_t r8(void){st^=st<<13;st^=st>>7;st^=st<<17;return (uint8_t)(st>>24);}
static int cmpi(const void*a,const void*b){return *(const int16_t*)a-*(const int16_t*)b;}
int main(int argc,char**argv){
  unsigned long T=argc>1?strtoul(argv[1],0,10):2000;
  static uint8_t buf[4*PARAM_N+64]; static int16_t a[PARAM_N],b[PARAM_N];
  st=0xdeadbeefcafe1234ULL^PARAM_N; for(int i=0;i<64;i++)r8();
  for(int eta=3;eta<=7;eta+=4){
    size_t nb=(size_t)((PARAM_N*(long)eta+3)/4);
    unsigned long msdiff=0;
    for(unsigned long t=0;t<T;t++){
      for(size_t i=0;i<nb;i++)buf[i]=r8();
      if(eta==3){cbd3(a,buf);}else{cbd7(a,buf);}
      cbd_eta_alg11(b,buf,eta,PARAM_N);
      qsort(a,PARAM_N,2,cmpi); qsort(b,PARAM_N,2,cmpi);
      if(memcmp(a,b,2*PARAM_N))msdiff++;
    }
    printf("  PARAMS=%d eta=%d: sorted-multiset differs in %lu / %lu buffers\n",PARAMS,eta,msdiff,T);
  }
  return 0;}
