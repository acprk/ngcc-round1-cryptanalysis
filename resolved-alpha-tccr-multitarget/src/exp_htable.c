// Exp A: is the /T speedup a real TOTAL-WORK speedup, i.e. is membership O(1)?
// Real submitted TCCR (256-bit set). T targets placed uniformly in a 2^B window.
// Genuine randomized search; membership via an open-addressing hash set (O(1)) vs linear scan (O(T)).
#include "tccr.h"
#include "drng.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define LB 32
DRNG_ctx drng_algorithm;
static void emb(uint32_t x, uint8_t* z, const uint8_t* base){ memcpy(z,base,LB); z[0]=x; z[1]=x>>8; z[2]=x>>16; z[3]=x>>24; }
int main(int argc,char**argv){
  int B=atoi(argv[1]), T=atoi(argv[2]), runs=atoi(argv[3]);
  srand(7); uint8_t s[LB],iv[16],base[LB];
  for(int i=0;i<LB;i++){s[i]=rand();base[i]=rand();} for(int i=0;i<16;i++)iv[i]=rand();
  uint32_t N=1u<<B, mask=N-1;
  // hash table: size = next pow2 >= 4T, key = first 8 bytes of image
  uint32_t hsz=1; while(hsz<(uint32_t)(4*T)) hsz<<=1; uint32_t hmask=hsz-1;
  uint64_t *ht=malloc(hsz*8); uint8_t *tg=malloc((size_t)T*LB);
  double ev_ht=0, probe_ht=0, ev_lin=0, cmp_lin=0;
  for(int r=0;r<runs;r++){
    memset(ht,0,hsz*8);
    uint32_t *pre=malloc(T*4);
    for(int t=0;t<T;t++){ uint32_t p=((uint32_t)rand()*2654435761u)&mask; pre[t]=p;
      uint8_t z[LB]; emb(p,z,base); tccr_hash(z,s,iv,tg+(size_t)t*LB,256);
      uint64_t k; memcpy(&k,tg+(size_t)t*LB,8); if(!k)k=1;
      uint32_t h=(uint32_t)((k*11400714819323198485ull)>>40)&hmask; while(ht[h]&&ht[h]!=k)h=(h+1)&hmask; ht[h]=k; }
    uint32_t start=((uint32_t)rand()*40503u)&mask;
    // --- hash-table search
    uint64_t ev=0,pr=0; int hit=0; uint8_t z[LB],h[LB];
    for(uint32_t c=0;c<N&&!hit;c++){ uint32_t x=(start+c)&mask; emb(x,z,base); tccr_hash(z,s,iv,h,256); ev++;
      uint64_t k; memcpy(&k,h,8); if(!k)k=1; uint32_t idx=(uint32_t)((k*11400714819323198485ull)>>40)&hmask;
      while(ht[idx]){ pr++; if(ht[idx]==k){hit=1;break;} idx=(idx+1)&hmask; } }
    ev_ht+=ev; probe_ht+=pr;
    // --- linear-scan search (same walk), count comparisons
    uint64_t ev2=0,cmp=0; hit=0;
    for(uint32_t c=0;c<N&&!hit;c++){ uint32_t x=(start+c)&mask; emb(x,z,base); tccr_hash(z,s,iv,h,256); ev2++;
      for(int t=0;t<T;t++){ cmp++; if(!memcmp(h,tg+(size_t)t*LB,8)){hit=1;break;} } }
    ev_lin+=ev2; cmp_lin+=cmp;
    free(pre);
  }
  printf("B=%d T=%d runs=%d\n",B,T,runs);
  printf("  hash-table: TCCR evals=%.0f  probes=%.2f/eval  =>  total work ~= evals (O(1) membership)\n",ev_ht/runs,probe_ht/ev_ht);
  printf("  linear    : TCCR evals=%.0f  comparisons=%.0f (=%.0fx evals)\n",ev_lin/runs,cmp_lin/runs,cmp_lin/ev_lin);
  printf("  model 2^B/(T+1)=%.0f  single-target 2^B/2=%.0f\n",(double)N/(T+1),N/2.0);
  return 0;
}
