/* Sub-ring projection harness for LoongKEM (Loong128).
   Links the UNMODIFIED reference implementation copied from src/.
   Verifies multiplication is negacyclic mod X^12+1 and dumps the STRUCTURED
   public rows b1 together with A1,A2 and the secret (s1,s2) so the ring-hom
   projection to R_4 can be checked. Secret dumped only for checking. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "drng.h"
#include "auxfunc.h"
#include "poly.h"
#include "KEM_Loong.h"

DRNG_ctx drng_algorithm;

static void pvec(FILE *f, const char *name, const int16_t *v, int n) {
    fprintf(f, "%s", name);
    for (int i = 0; i < n; i++) fprintf(f, " %d", v[i]);
    fprintf(f, "\n");
}

static int16_t smod(int32_t x){ int32_t r=x%Q; if(r<0)r+=Q; return r; }

/* schoolbook negacyclic mult mod (X^12+1) */
static void negmul(const int16_t*a,const int16_t*b,int16_t*c){
    int32_t t[2*N]; memset(t,0,sizeof(t));
    for(int i=0;i<N;i++)for(int j=0;j<N;j++)t[i+j]+=(int32_t)a[i]*b[j];
    for(int i=0;i<N;i++)c[i]=smod(t[i]-t[i+N]);
}

int main(int argc,char**argv){
    unsigned char nonce[64];
    for(int i=0;i<16;i++)memcpy(nonce+4*i,"lung",4);
    if(argc>1)nonce[0]=(unsigned char)atoi(argv[1]);
    init_random_number(&drng_algorithm,nonce,64);

    /* ring test using the scheme's own poly path is internal; do a direct test:
       compare negmul against the reference poly_mul via poly_mat_vec_mul with 1x1. */
    {
        int16_t a[N],b[N],c1[N],c2[N];
        unsigned char rb[4*N]; get_random_number(&drng_algorithm,rb,4*N*8);
        for(int i=0;i<N;i++){a[i]=((rb[2*i]<<8|rb[2*i+1])&0x1fff)%Q; b[i]=((rb[2*N+2*i]<<8|rb[2*N+2*i+1])&0x1fff)%Q;}
        poly_mat_vec_mul(a,b,c1,1,1);  /* uses poly_mul internally */
        negmul(a,b,c2);
        int bad=0; for(int i=0;i<N;i++) if(c1[i]!=c2[i]) bad++;
        printf("# ring_test poly_mul vs schoolbook negacyclic mod X^%d+1: mismatches=%d\n",N,bad);
    }

    unsigned char pk[PUBLICKEY_BYTES],sk[SECRETKEY_BYTES];
    unsigned char ct[CIPHERTEXT_BYTES],ss[SHARED_KEY_BYTES],ss2[SHARED_KEY_BYTES];
    unsigned long long l1,l2,l3,l4;
    kem_keygen(pk,&l1,sk,&l2);
    kem_enc(pk,l1,ss,&l3,ct,&l4);
    kem_dec(sk,l2,ct,l4,ss2,&l3);
    printf("# ss match: %d\n", memcmp(ss,ss2,SHARED_KEY_BYTES)==0);

    /* re-derive A from publicseed */
    size_t xlen = K1*K1*N+K1*K2*N+K2*K1*N+K2*K2*N*N;
    int16_t *A = malloc(sizeof(int16_t)*xlen);
    unsigned char *x = malloc(3*xlen);
    pseudoXOF(3*8*xlen, pk, SEED_BYTES*8, x);
    sample_vector(x,A,xlen);
    int16_t *A1=A;                       /* K1*K1 ring */
    int16_t *A2=A+K1*K1*N;               /* K1*K2 ring */

    /* secret from sk */
    int16_t s[K1*N+K2*N];
    decode_noise_vector(sk,s,K1*N+K2*N,4);
    int16_t *s1=s, *s2=s+K1*N;

    /* b1 decompressed from pk */
    int16_t b[K1*N], b1[K1*N];
    decode_vector(pk+SEED_BYTES,b,K1*N,DB);
    decompress(b,K1*N,b1,QBITS-DB);

    FILE*f=fopen(argc>2?argv[2]:"dump.txt","w");
    fprintf(f,"N %d\nK1 %d\nK2 %d\nQ %d\nETA %d\nDB %d\n",N,K1,K2,Q,ETA,DB);
    pvec(f,"A1",A1,K1*K1*N);
    pvec(f,"A2",A2,K1*K2*N);
    pvec(f,"s1",s1,K1*N);
    pvec(f,"s2",s2,K2*N);
    pvec(f,"b1",b1,K1*N);
    fclose(f);
    free(A); free(x);
    printf("# dumped Loong128 structured block\n");
    return 0;
}
