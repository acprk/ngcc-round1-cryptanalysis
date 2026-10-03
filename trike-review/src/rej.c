/* measure the real weak-key rejection rate of the shipped weak_key_test at FULL parameters */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "trike_params.h"
#define HALFR HALF_R
static uint32_t R_=PARAM_R;
static uint64_t rs[4];
static inline uint64_t rotl(uint64_t x,int k){return (x<<k)|(x>>(64-k));}
static uint64_t rnd(void){uint64_t r_=rotl(rs[1]*5,7)*9;uint64_t t=rs[1]<<17;rs[2]^=rs[0];rs[3]^=rs[1];rs[1]^=rs[2];rs[0]^=rs[3];rs[2]^=t;rs[3]=rotl(rs[3],45);return r_;}
static void seed_rng(uint64_t s){for(int i=0;i<4;i++){s^=s>>12;s^=s<<25;s^=s>>27;rs[i]=s*0x2545F4914F6CDD1DULL;}for(int i=0;i<16;i++)rnd();}
static inline uint32_t rnd_below(uint32_t m){return (uint32_t)(((__uint128_t)rnd()*m)>>64);}
static void samp(uint32_t*idx){for(uint32_t i=0;i<PARAM_D;i++){while(1){uint32_t c=rnd_below(R_);int dup=0;for(uint32_t j=0;j<i;j++)if(idx[j]==c){dup=1;break;}if(!dup){idx[i]=c;break;}}}}
static uint32_t *dist;
static uint64_t intra(const uint32_t*idx){
    for(uint32_t i=1;i<PARAM_D;i++)for(uint32_t j=0;j<i;j++){int32_t y=(int32_t)idx[j]-(int32_t)idx[i];if(y<0)y+=R_;if((uint32_t)y>=HALFR)y=R_-y;dist[y]++;}
    uint64_t res=0;for(uint32_t i=0;i<HALFR;i++){uint32_t m=dist[i];if(m>=2)res+=(uint64_t)m*(m-1)/2;dist[i]=0;}return res;}
static uint64_t inter(const uint32_t*a,const uint32_t*b){
    for(uint32_t i=0;i<PARAM_D;i++)for(uint32_t j=0;j<PARAM_D;j++){int32_t y=(int32_t)b[j]-(int32_t)a[i];if(y<0)y+=R_;dist[y]++;}
    uint64_t res=0;for(uint32_t i=0;i<R_;i++){uint32_t m=dist[i];if(m>=2)res+=(uint64_t)m*(m-1)/2;dist[i]=0;}return res;}
int main(int argc,char**argv){
    uint64_t n=argc>1?strtoull(argv[1],NULL,10):100000; seed_rng(argc>2?strtoull(argv[2],NULL,10):1);
    dist=calloc(R_,sizeof(uint32_t));
    uint32_t h0[PARAM_D],h1[PARAM_D],h2[PARAM_D];
    uint64_t rej=0, rej_intra=0, rej_inter=0; double s0sum=0,ssum=0; uint64_t s0max=0,smax=0;
    for(uint64_t k=0;k<n;k++){
        samp(h0);samp(h1);samp(h2);
        uint64_t a=intra(h0),b=intra(h1),c=intra(h2);
        uint64_t d=inter(h0,h1),e=inter(h1,h2),f=inter(h2,h0);
        int ri=(a>PARAM_S)||(b>PARAM_S)||(c>PARAM_S), ro=(d>PARAM_SS)||(e>PARAM_SS)||(f>PARAM_SS);
        rej+= (ri||ro); rej_intra+=ri; rej_inter+=ro;
        s0sum+=(a+b+c)/3.0; ssum+=(d+e+f)/3.0;
        uint64_t m1=a>b?a:b; if(c>m1)m1=c; if(m1>s0max)s0max=m1;
        uint64_t m2=d>e?d:e; if(f>m2)m2=f; if(m2>smax)smax=m2;
    }
    printf("R=%u d=%d S=%d SS=%d keys=%llu: rejected=%llu (%.4f%%)  [intra %.4f%%, inter %.4f%%]  mean intra s0=%.2f (max %llu)  mean inter=%.2f (max %llu)\n",
      R_,PARAM_D,PARAM_S,PARAM_SS,(unsigned long long)n,(unsigned long long)rej,100.0*rej/n,100.0*rej_intra/n,100.0*rej_inter/n,
      s0sum/n,(unsigned long long)s0max,ssum/n,(unsigned long long)smax);
    return 0;
}
