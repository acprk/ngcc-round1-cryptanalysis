#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "params.h"
#include "bch.h"
#ifndef ONLYDATA
#define ONLYDATA 1
#endif
static uint64_t s64=0x1234567ULL;
static uint64_t xr(void){s64^=s64<<13;s64^=s64>>7;s64^=s64<<17;return s64;}
static void flip(uint8_t*b,int bit){b[bit>>3]^=0x80>>(bit&7);}
/* generic: data bytes D, databits Db, ecc bits Eb ; nib=1 use nibble API */
static void run(const char*name,int hi,int nib,int Db,int Eb,int t){
  for(int e=1;e<=t+1;e++){int ok=0,flag=0,T=20000;
    for(int tr=0;tr<T;tr++){uint8_t d[64]={0},d0[64],ecc[16]={0};int Dbytes=(Db+7)/8;
      for(int i=0;i<Dbytes;i++)d[i]=xr(); if(Db%8) d[Dbytes-1]&=(uint8_t)(0xFF<<(8-Db%8));
      if(hi){ if(nib) encode_bch_high_nibbles(d,Db/4,ecc); else encode_bch_high(d,Dbytes,ecc);}
      else  { if(nib) encode_bch_low_nibbles(d,Db/4,ecc); else encode_bch_low(d,Dbytes,ecc);}
      memcpy(d0,d,64); int used[1100]={0};
      for(int k=0;k<e;k++){int p;do p=xr()%(ONLYDATA?Db:(Db+Eb));while(used[p]);used[p]=1; if(p<Db)flip(d,p);else flip(ecc,p-Db);}
      int r = hi? (nib?decode_bch_high_nibbles(d,Db/4,ecc):decode_bch_high(d,Dbytes,ecc)) : (nib?decode_bch_low_nibbles(d,Db/4,ecc):decode_bch_low(d,Dbytes,ecc));
      if(r<0)flag++; ok+=(memcmp(d,d0,Dbytes)==0);}
    printf("%s t=%d: %d errors -> data correct %d/%d, decoder returned -1 %d times\n",name,t,e,ok,T,flag);}
}
int main(){
#if WEAVER_MODE==1
  run("hi BCH(127,113,2) short 112+14",1,0,112,14,2); run("lo BCH(31,21,2) short 16+10",0,0,16,10,2);
#elif WEAVER_MODE==3
  run("hi BCH(255,223,4) short 220+32 (nibbles)",1,1,220,32,4); run("lo BCH(63,39,4) short 36+24 (nibbles)",0,1,36,24,4);
#else
  run("hi BCH(511,448,7) 448+63",1,0,448,63,7); run("lo BCH(127,78,7) short 64+49",0,0,64,49,7);
#endif
}
