/* MORNING-ATLAS (sign-15) verification tool. Linked against one unmodified parameter-set tree
 * (Reference_ or Optimized_Implementation/lwrdsaXXX). Nothing in the vendor sources is edited;
 * the scaled-down experiments interpose on two vendor functions with the GNU ld --wrap option:
 *   mucoll : --wrap=pseudoXOF        truncates ONLY the message representative mu to MU_TRUNC bytes
 *   seed   : --wrap=get_random_number counts the DRNG bits drawn by keygen / overrides them
 * Modes:
 *   chal T  : statistics of the shipped challenge() over T random inputs (byte-index dead zone)
 *   mal     : flip each unused bit of the challenge sign word of an honest signature
 *   mucoll  : generic collision of the (truncated) mu, then transfer of one signature
 *   seed B  : keygen consumes exactly 256 DRNG bits; pk/sk is a function of them; scaled
 *             seed-enumeration key recovery from pk alone with B unknown seed bits          */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "drng.h"
#include "auxfunc.h"
#include "SIG_AlgorithmInstance.h"
DRNG_ctx drng_algorithm;
void challenge(poly *c, const unsigned char mu[CRHBYTES], const polyveck *w1);
#if N==512
#define COFF (L*POLZ_SIZE_PACKED + 9*(OMEGA>>3) + K)   /* offset of c in the packed signature */
#else
#define COFF (L*POLZ_SIZE_PACKED + OMEGA + K)
#endif
static int level(void){ return CRYPTO_BYTES==2081?128:CRYPTO_BYTES==3365?192:N==256?256:512; }

#ifdef WRAP_XOF
#ifndef MU_TRUNC
#define MU_TRUNC 5
#endif
int __real_pseudoXOF(unsigned long long, const unsigned char *, unsigned long long, unsigned char *);
static unsigned long long mu_in_bits = 0;   /* (CRHBYTES + message length) * 8 of the mu call */
int __wrap_pseudoXOF(unsigned long long ob, const unsigned char *m, unsigned long long ib, unsigned char *o){
  int r = __real_pseudoXOF(ob, m, ib, o);
  if (ob == CRHBYTES*8 && ib == mu_in_bits) memset(o + MU_TRUNC, 0, CRHBYTES - MU_TRUNC); /* mu only */
  return r;
}
#endif
#ifdef WRAP_RNG
int __real_get_random_number(DRNG_ctx *, unsigned char *, unsigned long long);
static unsigned long long drawn_bits = 0; static int ncalls = 0;
static const unsigned char *forced = NULL;  /* if set: the keygen draw returns these bytes */
int __wrap_get_random_number(DRNG_ctx *d, unsigned char *out, unsigned long long bits){
  drawn_bits += bits; ncalls++;
  if (forced) { memcpy(out, forced, (bits+7)/8); return 0; }
  return __real_get_random_number(d, out, bits);
}
#endif

int main(int argc, char **argv){
  unsigned char seed[64]; for (int i=0;i<64;i++) seed[i]=(unsigned char)(i*13+5);
  init_random_number(&drng_algorithm, seed, 64);
  unsigned long long pkl, skl, snl; size_t ml = 8;
  unsigned char *pk=malloc(CRYPTO_PUBLICKEYBYTES), *sk=malloc(CRYPTO_SECRETKEYBYTES);
  unsigned char *sn=calloc(CRYPTO_BYTES+ml,1), *sn2=calloc(CRYPTO_BYTES+ml,1), m[8], mc[8];
  if (argc < 2) { fprintf(stderr, "usage: chal T | mal | mucoll | seed B\n"); return 2; }

  if (!strcmp(argv[1],"chal")) {
    int T = atoi(argv[2]); static long cnt[N]; long dead=0;
    unsigned char mu[CRHBYTES]; polyveck w1; memset(&w1,0,sizeof w1);
    for (int t=0;t<T;t++){
      get_random_number(&drng_algorithm, mu, CRHBYTES*8);
      for (int i=0;i<K;i++) for (int j=0;j<N;j++) w1.vec[i].coeffs[j]=(mu[(i+j)%CRHBYTES]+t+j)&7;
      poly c; challenge(&c, mu, &w1); int w=0;
      for (int j=0;j<N;j++) if (c.coeffs[j]) { cnt[j]++; w++; if (j>=256 && j<(int)(N-KAPPA)) dead++; }
      if (w != (int)KAPPA) printf("unexpected weight %d\n", w);
    }
    int reach=0; for (int j=0;j<N;j++) if (cnt[j]) reach++;
    double e=(double)T*KAPPA/N, chi=0; for (int j=0;j<N;j++) chi+=(cnt[j]-e)*(cnt[j]-e)/e;
    double expd = N>256 ? (double)T*KAPPA*(N-KAPPA-256)/N : 0;
    printf("ATLAS-%d N=%d KAPPA=%d T=%d: non-zeros at positions [256,%d): %ld (uniform: %.0f); positions ever hit %d/%d; chi2/df=%.1f\n",
           level(), N, KAPPA, T, N-KAPPA, dead, expd, reach, N, chi/(N-1));
    return 0;
  }
  sig_keygen(pk,&pkl,sk,&skl);
  for (size_t i=0;i<ml;i++) m[i]=(unsigned char)i;

  if (!strcmp(argv[1],"mal")) {
    sig_sign(sk,skl,m,ml,sn,&snl); memcpy(mc,m,ml); int v0=sig_verify(pk,pkl,sn,CRYPTO_BYTES+ml,mc,ml);
    int acc=0, tried=0;
    for (int bit=KAPPA; bit<64; bit++){
      memcpy(sn2,sn,CRYPTO_BYTES+ml); sn2[COFF + N/8 + bit/8] ^= (1u<<(bit%8));
      memcpy(mc,m,ml); if (sig_verify(pk,pkl,sn2,CRYPTO_BYTES+ml,mc,ml)==0 && memcmp(sn,sn2,CRYPTO_BYTES)) acc++; tried++;
    }
    memcpy(sn2,sn,CRYPTO_BYTES+ml); sn2[COFF + N/8] ^= 1; memcpy(mc,m,ml); int vc=sig_verify(pk,pkl,sn2,CRYPTO_BYTES+ml,mc,ml);
    printf("ATLAS-%d honest verify=%d; unused sign bits %d..63: %d/%d flips give a DIFFERENT byte string that verifies; control (flip used sign bit 0) verify=%d  [0=accept]\n",
           level(), v0, KAPPA, acc, tried, vc);
    return 0;
  }
#ifdef WRAP_XOF
  if (!strcmp(argv[1],"mucoll")) {
    mu_in_bits = (CRHBYTES + ml) * 8;
    uint8_t tr[CRHBYTES], buf[CRHBYTES+8], mu[CRHBYTES];
    pseudoXOF(CRHBYTES*8, pk, CRYPTO_PUBLICKEYBYTES*8, tr);          /* tr = CRH(pk), public */
    size_t NT = 1u<<22; uint64_t *tab = calloc(NT*2, 8);
    for (uint64_t i=1;;i++){
      memcpy(buf,tr,CRHBYTES); memcpy(buf+CRHBYTES,&i,8);
      pseudoXOF(CRHBYTES*8, buf, (CRHBYTES+8)*8, mu);                /* mu = CRH(tr || M), truncated */
      uint64_t k=0; memcpy(&k,mu,MU_TRUNC); size_t p=(size_t)((k*0x9E3779B97F4A7C15ull)>>42);
      while (tab[2*p]) {
        if (tab[2*p]==k+1) {
          uint64_t j=tab[2*p+1]; unsigned char m1[8], m2[8]; memcpy(m1,&j,8); memcpy(m2,&i,8);
          printf("ATLAS-%d, mu truncated to %d bytes: collision CRH(tr||M1)=CRH(tr||M2) after %llu hashes (public key only)\n",
                 level(), MU_TRUNC, (unsigned long long)i);
          sig_sign(sk,skl,m1,8,sn,&snl);                              /* the ONE chosen-message signing query */
          memcpy(mc,m1,8); int a=sig_verify(pk,pkl,sn,CRYPTO_BYTES+8,mc,8);
          memcpy(mc,m2,8); int b=sig_verify(pk,pkl,sn,CRYPTO_BYTES+8,mc,8);
          uint64_t z=i+999; memcpy(mc,&z,8); int c=sig_verify(pk,pkl,sn,CRYPTO_BYTES+8,mc,8);
          printf("  signature on M1: verify(M1)=%d  verify(M2, never signed)=%d  control verify(M3)=%d  [0=accept]\n", a, b, c);
          return (a==0 && b==0 && c!=0) ? 0 : 1;
        }
        p=(p+1)&(NT-1);
      }
      tab[2*p]=k+1; tab[2*p+1]=i;
    }
  }
#endif
#ifdef WRAP_RNG
  if (!strcmp(argv[1],"seed")) {
    int B = argc>2 ? atoi(argv[2]) : 12;
    /* (a) how many DRNG bits does one keygen consume? */
    drawn_bits=0; ncalls=0; sig_keygen(pk,&pkl,sk,&skl); unsigned long long kg_bits = drawn_bits;
    printf("ATLAS-%d: one sig_keygen draws %llu DRNG bits in %d call(s)\n", level(), drawn_bits, ncalls);
    /* (b) pk/sk is a function of those bits only: same 32 bytes, DRNG in two unrelated states */
    unsigned char S[32]; for (int i=0;i<32;i++) S[i]=(unsigned char)(0xA5^(i*29));
    unsigned char *pk2=malloc(CRYPTO_PUBLICKEYBYTES), *sk2=malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char sA[64], sB[64]; memset(sA,1,64); memset(sB,2,64);
    init_random_number(&drng_algorithm,sA,64); forced=S; sig_keygen(pk,&pkl,sk,&skl);
    init_random_number(&drng_algorithm,sB,64); forced=S; sig_keygen(pk2,&pkl,sk2,&skl); forced=NULL;
    printf("  same 256-bit draw, different DRNG states: pk %s, sk %s\n",
           memcmp(pk,pk2,CRYPTO_PUBLICKEYBYTES)?"DIFFER":"identical", memcmp(sk,sk2,CRYPTO_SECRETKEYBYTES)?"DIFFER":"identical");
    /* (c) scaled seed enumeration: the victim's draw has B (<=16) unknown bits; attacker sees pk only */
    if (B < 1 || B > 16) B = 12;
    unsigned char V[32]; memcpy(V,S,32); uint32_t secret = 0xB5A5u & ((1u<<B)-1);
    V[0]=secret&0xff; V[1]=(V[1]&~(((1u<<B)-1)>>8)) | ((secret>>8)&0xff);
    forced=V; sig_keygen(pk,&pkl,sk,&skl);                          /* victim; sk kept only for SCORING */
    unsigned char G[32]; memcpy(G,V,32);
    for (uint32_t g=0; g < (1u<<B); g++){
      G[0]=g&0xff; G[1]=(V[1]&~(((1u<<B)-1)>>8)) | ((g>>8)&0xff);
      forced=G; sig_keygen(pk2,&pkl,sk2,&skl);
      if (!memcmp(pk,pk2,CRYPTO_PUBLICKEYBYTES)) {
        forced=NULL;
        printf("  scaled enumeration (%d unknown seed bits): pk matched after %u keygens; recovered sk == victim sk [SCORING]: %s\n",
               B, g+1, memcmp(sk,sk2,CRYPTO_SECRETKEYBYTES)?"NO":"yes");
        init_random_number(&drng_algorithm,sA,64);
        sig_sign(sk2,skl,m,ml,sn,&snl); memcpy(mc,m,ml);           /* sign with the RECOVERED key */
        printf("  signature made with the recovered key verifies under the victim pk: %s\n", sig_verify(pk,pkl,sn,CRYPTO_BYTES+ml,mc,ml)==0?"yes":"NO");
        printf("  => full-width key recovery = 2^%llu keygens vs claimed %d-bit\n", kg_bits, level());
        return 0;
      }
    }
    printf("  not found\n"); return 1;
  }
#endif
  fprintf(stderr,"mode not built in this binary\n"); return 2;
}
