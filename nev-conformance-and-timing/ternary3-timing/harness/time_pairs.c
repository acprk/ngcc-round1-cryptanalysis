/* Interleaved paired-median timing of kem_cca_dec on two ciphertext classes.
 * Clean (non-instrumented) build.  Never batches: the two classes strictly
 * alternate and the within-pair order flips every pair, so first-position and
 * cache-warming bias cancels in the paired difference.
 *   mode=ab : class A = LOW-rejection cts, class B = HIGH-rejection cts
 *   mode=aa : NEGATIVE CONTROL, both classes drawn from disjoint halves of LOW
 *   mode=bb : NEGATIVE CONTROL, both from disjoint halves of HIGH            */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "cca.h"

static inline uint64_t rdtsc(void){
    unsigned lo,hi; uint32_t aux;
    __asm__ __volatile__("lfence");
    __asm__ __volatile__("rdtscp":"=a"(lo),"=d"(hi),"=c"(aux));
    __asm__ __volatile__("lfence");
    return ((uint64_t)hi<<32)|lo;
}
static int cmpd(const void*x,const void*y){ long long a=*(const long long*)x,b=*(const long long*)y; return a<b?-1:(a>b); }
static double med(long long *v,int n){ qsort(v,n,sizeof(long long),cmpd); return n&1? (double)v[n/2] : 0.5*(v[n/2-1]+v[n/2]); }

int main(int argc,char**argv){
    const char*path=argv[1]; const char*mode=argv[2];
    int pairs = argc>3?atoi(argv[3]):2000;
    int batches = argc>4?atoi(argv[4]):15;
    FILE*f=fopen(path,"rb"); if(!f){perror("open");return 1;}
    uint32_t hdr[6]; if(fread(hdr,sizeof(hdr),1,f)!=1){return 1;}
    int ctb=hdr[1], skb=hdr[2], nlo=hdr[3], nhi=hdr[4];
    if((int)hdr[0]!=PARAMS){fprintf(stderr,"PARAMS mismatch %u vs %d\n",hdr[0],PARAMS);return 1;}
    if(ctb!=KEM_CCA_CT_BYTES||skb!=KEM_CCA_SK_BYTES){fprintf(stderr,"size mismatch\n");return 1;}
    uint8_t*sk=malloc(skb); if(fread(sk,1,skb,f)!=(size_t)skb)return 1;
    uint8_t*lo=malloc((size_t)nlo*ctb), *hi=malloc((size_t)nhi*ctb);
    if(fread(lo,1,(size_t)nlo*ctb,f)!=(size_t)nlo*ctb)return 1;
    if(fread(hi,1,(size_t)nhi*ctb,f)!=(size_t)nhi*ctb)return 1;
    fclose(f);

    uint8_t *A,*B; int nA,nB;
    if(!strcmp(mode,"ab")){A=lo;nA=nlo;B=hi;nB=nhi;}
    else if(!strcmp(mode,"aa")){A=lo;nA=nlo/2;B=lo+(size_t)(nlo/2)*ctb;nB=nlo-nlo/2;}
    else {A=hi;nA=nhi/2;B=hi+(size_t)(nhi/2)*ctb;nB=nhi-nhi/2;}
    if(nA<2||nB<2){fprintf(stderr,"not enough cts (%d,%d)\n",nA,nB);return 1;}

    uint8_t ss[SEED_BYTES]; uint8_t *ctbuf=malloc(ctb);
    long long *d=malloc(sizeof(long long)*pairs);
    long long *ta=malloc(sizeof(long long)*pairs), *tb=malloc(sizeof(long long)*pairs);
    volatile int sink=0;
    /* warm up */
    for(int i=0;i<20000;i++){ memcpy(ctbuf,A+(size_t)(i%nA)*ctb,ctb); sink+=kem_cca_dec(ss,ctbuf,sk); }

    printf("# %s mode=%s PARAMS=%d pairs=%d batches=%d nA=%d nB=%d\n",path,mode,PARAMS,pairs,batches,nA,nB);
    int signpos=0; double mall[256];
    for(int b=0;b<batches;b++){
        for(int j=0;j<pairs;j++){
            const uint8_t *pa=A+(size_t)((j+b*pairs)%nA)*ctb;
            const uint8_t *pb=B+(size_t)((j+b*pairs)%nB)*ctb;
            uint64_t t0,t1,t2,t3;
            if(((b+j)&1)==0){
                memcpy(ctbuf,pa,ctb); t0=rdtsc(); sink+=kem_cca_dec(ss,ctbuf,sk); t1=rdtsc();
                memcpy(ctbuf,pb,ctb); t2=rdtsc(); sink+=kem_cca_dec(ss,ctbuf,sk); t3=rdtsc();
                ta[j]=t1-t0; tb[j]=t3-t2;
            } else {
                memcpy(ctbuf,pb,ctb); t2=rdtsc(); sink+=kem_cca_dec(ss,ctbuf,sk); t3=rdtsc();
                memcpy(ctbuf,pa,ctb); t0=rdtsc(); sink+=kem_cca_dec(ss,ctbuf,sk); t1=rdtsc();
                ta[j]=t1-t0; tb[j]=t3-t2;
            }
            d[j]=tb[j]-ta[j];
        }
        long long *cp=malloc(sizeof(long long)*pairs);
        memcpy(cp,ta,sizeof(long long)*pairs); double ma=med(cp,pairs);
        memcpy(cp,tb,sizeof(long long)*pairs); double mb=med(cp,pairs);
        memcpy(cp,d ,sizeof(long long)*pairs); double md=med(cp,pairs);
        free(cp);
        if(md>0) signpos++;
        mall[b<256?b:255]=md;
        printf("batch %2d  med_tA=%.0f  med_tB=%.0f  med(tB-tA)=%+8.1f  (medB-medA=%+8.1f)\n",b,ma,mb,md,mb-ma);
    }
    long long *cp=malloc(sizeof(long long)*batches);
    for(int b=0;b<batches;b++) cp[b]=(long long)mall[b];
    printf("SUMMARY mode=%s  sign-positive batches=%d/%d  median-of-batch-medians=%+.1f cycles  sink=%d\n",
           mode, signpos, batches, med(cp,batches), sink);
    return 0;
}
