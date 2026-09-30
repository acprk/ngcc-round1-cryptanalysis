/* Fixed-vs-fixed per-message test: does decapsulation time depend on WHICH
 * honest ciphertext (hence on the decrypted m') is supplied?
 * For each pair of fixed ciphertexts (c0,c1) the two are interleaved one
 * decapsulation at a time with the within-pair order flipped every iteration.
 * NEGATIVE CONTROL for every pair: the identical experiment with c1 := c0, so
 * any residual is pure ordering/cache bias. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "api.h"
#include "cca.h"
static inline uint64_t rdtsc(void){unsigned lo,hi;uint32_t aux;
 __asm__ __volatile__("lfence");__asm__ __volatile__("rdtscp":"=a"(lo),"=d"(hi),"=c"(aux));
 __asm__ __volatile__("lfence");return ((uint64_t)hi<<32)|lo;}
static int cmpd(const void*x,const void*y){long long a=*(const long long*)x,b=*(const long long*)y;return a<b?-1:(a>b);}
static double med(long long*v,int n){qsort(v,n,sizeof(long long),cmpd);return n&1?(double)v[n/2]:0.5*(v[n/2-1]+v[n/2]);}
#define NP 32
int main(int argc,char**argv){
    int R=argc>1?atoi(argv[1]):3000;
    uint8_t *pk=malloc(KEM_CCA_PK_BYTES),*sk=malloc(KEM_CCA_SK_BYTES);
    uint8_t *cts=malloc((size_t)NP*KEM_CCA_CT_BYTES),ss[SEED_BYTES];
    kem_cca_keygen(pk,sk);
    for(int j=0;j<NP;j++) kem_cca_enc(ss,cts+(size_t)j*KEM_CCA_CT_BYTES,pk);
    long long *d=malloc(sizeof(long long)*R);
    uint8_t *cb=malloc(KEM_CCA_CT_BYTES); volatile int sink=0;
    for(int i=0;i<20000;i++){memcpy(cb,cts,KEM_CCA_CT_BYTES);sink+=kem_cca_dec(ss,cb,sk);}
    double worst=0,worstnull=0; int nsig=0;
    printf("# PARAMS=%d NP=%d R=%d  (pair = two fixed honest ciphertexts)\n",PARAMS,NP,R);
    for(int p=0;p<NP/2;p++) for(int ctl=0;ctl<2;ctl++){
        const uint8_t *A=cts+(size_t)(2*p)*KEM_CCA_CT_BYTES;
        const uint8_t *B=ctl? A : cts+(size_t)(2*p+1)*KEM_CCA_CT_BYTES;
        for(int r=0;r<R;r++){
            uint64_t t0,t1,t2,t3;
            if(r&1){ memcpy(cb,A,KEM_CCA_CT_BYTES);t0=rdtsc();sink+=kem_cca_dec(ss,cb,sk);t1=rdtsc();
                     memcpy(cb,B,KEM_CCA_CT_BYTES);t2=rdtsc();sink+=kem_cca_dec(ss,cb,sk);t3=rdtsc(); }
            else   { memcpy(cb,B,KEM_CCA_CT_BYTES);t2=rdtsc();sink+=kem_cca_dec(ss,cb,sk);t3=rdtsc();
                     memcpy(cb,A,KEM_CCA_CT_BYTES);t0=rdtsc();sink+=kem_cca_dec(ss,cb,sk);t1=rdtsc(); }
            d[r]=(long long)(t3-t2)-(long long)(t1-t0);
        }
        double m=med(d,R);
        if(ctl){ if(fabs(m)>worstnull) worstnull=fabs(m); }
        else   { if(fabs(m)>worst) worst=fabs(m); if(fabs(m)>40) nsig++;
                 printf("pair %2d  med(tB-tA)=%+8.1f\n",p,m); }
    }
    printf("SUMMARY PARAMS=%d  worst |median delta| over %d fixed pairs = %.1f cycles ; "
           "worst same-ciphertext NULL = %.1f cycles ; pairs above 40cyc = %d/%d ; sink=%d\n",
           PARAMS,NP/2,worst,worstnull,nsig,NP/2,sink);
    return 0;
}
