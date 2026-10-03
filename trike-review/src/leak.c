#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "KEM_AlgorithmInstance.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
int main(int argc,char**argv){
    int n = argc>1? atoi(argv[1]) : 200;
    unsigned char seed[64]; for(int i=0;i<64;i++) seed[i]=i;
    init_random_number(&drng_algorithm, seed, 64);
    unsigned long long pl,sl,cl,ssl;
    unsigned char *pk=malloc(kem_get_pk_len_bytes()),*sk=malloc(kem_get_sk_len_bytes());
    unsigned char *ct=malloc(kem_get_ct_len_bytes()),*ss=malloc(kem_get_ss_len_bytes()),*ss2=malloc(kem_get_ss_len_bytes());
    kem_keygen(pk,&pl,sk,&sl);
    kem_enc(pk,pl,ss,&ssl,ct,&cl);
    kem_dec(sk,sl,ct,cl,ss2,&ssl);
    printf("ss match: %s\n", memcmp(ss,ss2,ssl)?"NO":"yes");
    size_t before = mallinfo2().uordblks;
    for(int i=0;i<n;i++) kem_dec(sk,sl,ct,cl,ss2,&ssl);
    size_t after = mallinfo2().uordblks;
    printf("decaps=%d  heap in use before=%zu after=%zu  delta=%zu  per-decap=%.1f bytes\n",
        n,before,after,after-before,(double)(after-before)/n);
    size_t b2 = mallinfo2().uordblks;
    for(int i=0;i<n;i++) kem_enc(pk,pl,ss,&ssl,ct,&cl);
    printf("encaps=%d  delta=%zu per-encap=%.1f bytes\n",n,mallinfo2().uordblks-b2,(double)(mallinfo2().uordblks-b2)/n);
    size_t b3 = mallinfo2().uordblks;
    for(int i=0;i<10;i++) kem_keygen(pk,&pl,sk,&sl);
    printf("keygen=10 delta=%zu per-keygen=%.1f bytes\n",mallinfo2().uordblks-b3,(double)(mallinfo2().uordblks-b3)/10);
    return 0;
}
