/* Shared helpers: spec-faithful AFS-KEM-BW composite keys (spec Fig. 2/3) built only from
 * the submitted reference primitives. Level-agnostic (C128/C256/C512 via REF). */
#ifndef AFS_COMMON_H
#define AFS_COMMON_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/random.h>
#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "auxfunc.h"
#include "drng.h"
#define L  KYBER_SYMBYTES
#define PK KYBER_PUBLICKEYBYTES
#define SK KYBER_SECRETKEYBYTES
#define CT KYBER_CIPHERTEXTBYTES
/* C256/C512 route the library's randombytes() to this global DRNG; we never call it, but the
 * symbol must exist. All randomness used below comes from the OS via rnd(). */
DRNG_ctx drng_algorithm;
static void rnd(unsigned char *x, size_t n){ while(n){ ssize_t r=getrandom(x,n,0); if(r<0){perror("getrandom");exit(1);} x+=r; n-=r; } }
typedef struct { unsigned char pk[PK], sk[SK]; } party;
static void keygen(party *P){ unsigned char c[2*L]; rnd(c,sizeof c); crypto_kem_keypair_derand(P->pk,P->sk,c); }
/* cpk = pk + pk_e(seed), csk = (s + s_e, z)   (spec Fig. 2 EKeyGen + Fig. 3) */
static void composite(const party *P, const unsigned char seed[L], unsigned char *cpk, unsigned char *csk){
  unsigned char pke[KYBER_INDCPA_PUBLICKEYBYTES], ske[KYBER_INDCPA_SECRETKEYBYTES]; polyvec a,b,c;
  indcpa_keypair_ekeygen(P->pk,seed,pke,ske);
  memcpy(csk,P->sk,SK);
  polyvec_frombytes(&a,P->sk); polyvec_frombytes(&b,ske); polyvec_add(&c,&a,&b); polyvec_reduce(&c); polyvec_tobytes(csk,&c);
  polyvec_frombytes(&a,P->pk); polyvec_frombytes(&b,pke); polyvec_add(&c,&a,&b); polyvec_reduce(&c); polyvec_tobytes(cpk,&c);
  memcpy(cpk+KYBER_POLYVECBYTES,P->pk+KYBER_POLYVECBYTES,L);
  memcpy(csk+KYBER_INDCPA_SECRETKEYBYTES,cpk,PK);
  memcpy(csk+SK-PREFIXHASHBYTES-L,cpk,PREFIXHASHBYTES);   /* ID(cpk), as in the submitted wrapper */
}
/* pk' = cpk - pk_e(seed)   (spec: ExtractPK) */
static void extract(const unsigned char *cpk, const unsigned char seed[L], unsigned char *pk){
  unsigned char pke[KYBER_INDCPA_PUBLICKEYBYTES], ske[KYBER_INDCPA_SECRETKEYBYTES]; polyvec a,b,c;
  indcpa_keypair_ekeygen(cpk,seed,pke,ske); polyvec_frombytes(&a,cpk); polyvec_frombytes(&b,pke);
  polyvec_sub(&c,&a,&b); polyvec_reduce(&c); polyvec_tobytes(pk,&c); memcpy(pk+KYBER_POLYVECBYTES,cpk+KYBER_POLYVECBYTES,L);
}
/* (K_SESSION, K_ENC^A, K_ENC^B) = PRF(K_A, K_B), PRF = the ICCS pseudoXOF (as in the wrapper) */
static void prf(const unsigned char *KA, const unsigned char *KB, unsigned char out[3*L]){
  unsigned char in[2*L]; memcpy(in,KA,L); memcpy(in+L,KB,L); pseudoXOF(3ULL*L*8,in,2ULL*L*8,out); }
static void enc(unsigned char *ct, unsigned char *K, const unsigned char *pk){ unsigned char c[L]; rnd(c,L); crypto_kem_enc_derand(ct,K,pk,c); }
static void xorL(unsigned char *o,const unsigned char *a,const unsigned char *b){ for(int i=0;i<L;i++) o[i]=a[i]^b[i]; }
#endif
