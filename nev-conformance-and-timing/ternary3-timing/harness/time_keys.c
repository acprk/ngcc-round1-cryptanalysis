/* Is decapsulation time a function of the secret key?
 * K independent keypairs, each with its own pool of honest ciphertexts.  Keys
 * are visited strictly round-robin, one decapsulation each (never batched), so
 * drift and cache state are shared.  NEGATIVE CONTROL: with argv[2]=dup, slot 1
 * holds a byte-identical copy of key 0, so slot0-vs-slot1 is a true null. */
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
#define K 8
#define NCT 256
int main(int argc,char**argv){
    int reps=argc>1?atoi(argv[1]):4000;
    int dup = argc>2 && !strcmp(argv[2],"dup");
    uint8_t *pk[K],*sk[K],*ct[K]; uint8_t ss[SEED_BYTES];
    for(int k=0;k<K;k++){
        pk[k]=malloc(KEM_CCA_PK_BYTES); sk[k]=malloc(KEM_CCA_SK_BYTES);
        ct[k]=malloc((size_t)NCT*KEM_CCA_CT_BYTES);
        kem_cca_keygen(pk[k],sk[k]);
    }
    if(dup){ memcpy(sk[1],sk[0],KEM_CCA_SK_BYTES); memcpy(pk[1],pk[0],KEM_CCA_PK_BYTES); }
    for(int k=0;k<K;k++) for(int j=0;j<NCT;j++)
        kem_cca_enc(ss,ct[k]+(size_t)j*KEM_CCA_CT_BYTES,pk[k]);
    long long *t[K]; for(int k=0;k<K;k++) t[k]=malloc(sizeof(long long)*reps);
    uint8_t *cb=malloc(KEM_CCA_CT_BYTES); volatile int sink=0;
    for(int i=0;i<20000;i++){memcpy(cb,ct[0],KEM_CCA_CT_BYTES);sink+=kem_cca_dec(ss,cb,sk[0]);}
    for(int r=0;r<reps;r++) for(int k=0;k<K;k++){
        memcpy(cb,ct[k]+(size_t)(r%NCT)*KEM_CCA_CT_BYTES,KEM_CCA_CT_BYTES);
        uint64_t a=rdtsc(); sink+=kem_cca_dec(ss,cb,sk[k]); uint64_t z=rdtsc();
        t[k][r]=z-a;
    }
    printf("# PARAMS=%d K=%d reps=%d dup=%d\n",PARAMS,K,reps,dup);
    double m[K],lo=1e18,hi=-1e18;
    for(int k=0;k<K;k++){m[k]=med(t[k],reps);printf("key %d median=%.0f\n",k,m[k]);
        if(m[k]<lo)lo=m[k]; if(m[k]>hi)hi=m[k];}
    printf("SUMMARY PARAMS=%d dup=%d  spread(max-min over %d keys)=%.0f cycles  key0-key1=%+.0f  base=%.0f  rel=%.3e  sink=%d\n",
           PARAMS,dup,K,hi-lo,m[0]-m[1],m[0],(hi-lo)/m[0],sink);
    return 0;
}
