/* Dump (rejection_count, seed) for random sampler seeds. Instrumented build. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "sample.h"
#include "randombytes.h"
extern long long g_scan,g_rej,g_refill,g_veciter,g_tailacc;
int main(int argc,char**argv){
    int M=argc>1?atoi(argv[1]):100000; const char*out=argv[2];
    uint8_t seed[SEED_BYTES]; poly r;
    FILE*f=fopen(out,"wb");
    uint32_t h[3]={(uint32_t)PARAMS,(uint32_t)SEED_BYTES,(uint32_t)M}; fwrite(h,sizeof(h),1,f);
    long long s=0,mn=1<<30,mx=-1,rf=0;
    for(int k=0;k<M;k++){
        randombytes(seed,SEED_BYTES);
        g_scan=g_rej=g_refill=0;
        poly_sample_r(&r,seed,0);
        int32_t rr=(int32_t)g_rej; fwrite(&rr,4,1,f); fwrite(seed,1,SEED_BYTES,f);
        s+=g_rej; rf+=g_refill; if(g_rej<mn)mn=g_rej; if(g_rej>mx)mx=g_rej;
    }
    fclose(f);
    printf("PARAMS=%d ETA_R=%d M=%d  mean_rej=%.3f min=%lld max=%lld refills=%lld\n",
           PARAMS,
#ifdef ETA_R
           ETA_R,
#else
           -1,
#endif
           M,(double)s/M,mn,mx,rf);
    return 0;
}
