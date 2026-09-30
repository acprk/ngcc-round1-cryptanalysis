/* Isolated timing of poly_sample_r (== poly_bias3_ternary for ETA_R=9), bucketed
 * by exact rejection count, round-robin over buckets. Clean build. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "sample.h"
static inline uint64_t rdtsc(void){unsigned lo,hi;uint32_t aux;
 __asm__ __volatile__("lfence");__asm__ __volatile__("rdtscp":"=a"(lo),"=d"(hi),"=c"(aux));
 __asm__ __volatile__("lfence");return ((uint64_t)hi<<32)|lo;}
static int cmpd(const void*x,const void*y){long long a=*(const long long*)x,b=*(const long long*)y;return a<b?-1:(a>b);}
static double med(long long*v,int n){qsort(v,n,sizeof(long long),cmpd);return n&1?(double)v[n/2]:0.5*(v[n/2-1]+v[n/2]);}
#define NB 48
int main(int argc,char**argv){
    const char*p=argv[1]; int reps=argc>2?atoi(argv[2]):20000;
    FILE*f=fopen(p,"rb"); uint32_t h[3]; if(fread(h,sizeof(h),1,f)!=1)return 1;
    if((int)h[0]!=PARAMS||(int)h[1]!=SEED_BYTES)return fprintf(stderr,"mismatch\n"),1;
    int M=h[2],SB=SEED_BYTES;
    static uint8_t*bk[NB]; static int bn[NB]; int cap=8192;
    for(int i=0;i<NB;i++){bk[i]=malloc((size_t)cap*SB);bn[i]=0;}
    uint8_t*tmp=malloc(SB);
    for(int k=0;k<M;k++){int32_t r; if(fread(&r,4,1,f)!=1)break; if(fread(tmp,1,SB,f)!=(size_t)SB)break;
        if(r>=0&&r<NB&&bn[r]<cap){memcpy(bk[r]+(size_t)bn[r]*SB,tmp,SB);bn[r]++;}}
    fclose(f);
    int use[NB],nu=0; for(int i=0;i<NB;i++) if(bn[i]>=100) use[nu++]=i;
    printf("# %s PARAMS=%d reps=%d nbuckets=%d\n",p,PARAMS,reps,nu);
    if(nu<3)return 1;
    long long**t=malloc(sizeof(long long*)*nu); for(int i=0;i<nu;i++)t[i]=malloc(sizeof(long long)*reps);
    poly rr; volatile long sink=0;
    for(int i=0;i<50000;i++){poly_sample_r(&rr,bk[use[0]],0);sink+=rr.coeffs[0];}
    for(int r=0;r<reps;r++) for(int i=0;i<nu;i++){
        int ii=(i+r)%nu,b=use[ii];
        uint64_t a=rdtsc(); poly_sample_r(&rr,bk[b]+(size_t)(r%bn[b])*SB,0); uint64_t z=rdtsc();
        sink+=rr.coeffs[0]; t[ii][r]=z-a;
    }
    printf("rej   n      median_cycles\n");
    double sx=0,sy=0,sxx=0,sxy=0;
    for(int i=0;i<nu;i++){double m=med(t[i],reps);printf("%3d  %5d   %.0f\n",use[i],bn[use[i]],m);
        double X=use[i];sx+=X;sy+=m;sxx+=X*X;sxy+=X*m;}
    printf("SLOPE %.2f cycles/rejection (isolated poly_sample_r, OLS over %d buckets) sink=%ld\n",
           (nu*sxy-sx*sy)/(nu*sxx-sx*sx),nu,sink);
    return 0;
}
