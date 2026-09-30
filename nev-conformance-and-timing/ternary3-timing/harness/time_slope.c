/* Median decapsulation cycles as a function of the exact number of rejected
 * bytes the FO re-encryption's ternary3 will incur.  Buckets are visited
 * strictly round-robin (one decapsulation each, never batched), so drift and
 * cache state are shared across all buckets. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "cca.h"
static inline uint64_t rdtsc(void){unsigned lo,hi;uint32_t aux;
 __asm__ __volatile__("lfence");__asm__ __volatile__("rdtscp":"=a"(lo),"=d"(hi),"=c"(aux));
 __asm__ __volatile__("lfence");return ((uint64_t)hi<<32)|lo;}
static int cmpd(const void*x,const void*y){long long a=*(const long long*)x,b=*(const long long*)y;return a<b?-1:(a>b);}
static double med(long long*v,int n){qsort(v,n,sizeof(long long),cmpd);return n&1?(double)v[n/2]:0.5*(v[n/2-1]+v[n/2]);}
#define NB 32
int main(int argc,char**argv){
    const char*path=argv[1]; int reps=argc>2?atoi(argv[2]):400;
    FILE*f=fopen(path,"rb"); uint32_t h[4]; if(fread(h,sizeof(h),1,f)!=1)return 1;
    int ctb=h[1],skb=h[2],M=h[3];
    if((int)h[0]!=PARAMS||ctb!=KEM_CCA_CT_BYTES)return fprintf(stderr,"mismatch\n"),1;
    uint8_t*sk=malloc(skb); if(fread(sk,1,skb,f)!=(size_t)skb)return 1;
    /* bucket by rejection count */
    static uint8_t *bk[NB]; static int bn[NB];
    int cap=4096; for(int i=0;i<NB;i++){bk[i]=malloc((size_t)cap*ctb);bn[i]=0;}
    for(int k=0;k<M;k++){int32_t r;uint8_t*tmp=malloc(ctb);
        if(fread(&r,4,1,f)!=1)break; if(fread(tmp,1,ctb,f)!=(size_t)ctb)break;
        if(r>=0&&r<NB&&bn[r]<cap){memcpy(bk[r]+(size_t)bn[r]*ctb,tmp,ctb);bn[r]++;}
        free(tmp);}
    fclose(f);
    /* keep buckets with enough members */
    int use[NB],nu=0; for(int i=0;i<NB;i++) if(bn[i]>=40) use[nu++]=i;
    printf("# %s PARAMS=%d reps=%d buckets:",path,PARAMS,reps);
    for(int i=0;i<nu;i++) printf(" %d(n=%d)",use[i],bn[use[i]]); printf("\n");
    if(nu<3){fprintf(stderr,"too few buckets\n");return 1;}
    long long **t=malloc(sizeof(long long*)*nu);
    for(int i=0;i<nu;i++) t[i]=malloc(sizeof(long long)*reps);
    uint8_t ss[SEED_BYTES],*cb=malloc(ctb); volatile int sink=0;
    for(int i=0;i<20000;i++){memcpy(cb,bk[use[0]],ctb);sink+=kem_cca_dec(ss,cb,sk);}
    for(int r=0;r<reps;r++)
        for(int i=0;i<nu;i++){
            int b=use[(i+r)%nu];                       /* rotate bucket order too */
            int ii=(i+r)%nu;
            memcpy(cb,bk[b]+(size_t)(r%bn[b])*ctb,ctb);
            uint64_t a=rdtsc(); sink+=kem_cca_dec(ss,cb,sk); uint64_t z=rdtsc();
            t[ii][r]=z-a;
        }
    printf("rej   n     median_cycles\n");
    double x0=-1,y0=0;
    for(int i=0;i<nu;i++){ double m=med(t[i],reps);
        printf("%3d  %4d   %.0f\n",use[i],bn[use[i]],m);
        if(x0<0){x0=use[i];y0=m;} }
    /* least squares slope */
    double sx=0,sy=0,sxx=0,sxy=0;
    for(int i=0;i<nu;i++){double X=use[i],Y=med(t[i],reps);sx+=X;sy+=Y;sxx+=X*X;sxy+=X*Y;}
    double sl=(nu*sxy-sx*sy)/(nu*sxx-sx*sx);
    printf("SLOPE %.2f cycles per rejected byte (OLS over %d buckets)  sink=%d\n",sl,nu,sink);
    return 0;
}
