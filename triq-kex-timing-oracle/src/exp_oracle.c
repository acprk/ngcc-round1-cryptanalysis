// P1 foundation: idealized decode-oracle experiment against real TriQ-128 PKE.
// Goal of this first step: establish an oracle whose 1-bit answer leaks the
// support of the secret y. We have ground-truth y (re-derived from the seed)
// purely for instrumentation/verification; the *attack* logic will only ever
// consult submit_decode() (the oracle), never y directly.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "parameters.h"
#include "symmetric.h"
#include "vector.h"
#include "parsing.h"
#include "triq_pke.h"
#include "data_structures.h"

// --- helpers on bit-packed vectors of PARAM_N bits ---
static inline void set_bit(uint64_t *v,int i){ v[i>>6] |= (UINT64_C(1)<<(i&63)); }
static inline int get_bit(const uint64_t *v,int i){ return (v[i>>6]>>(i&63))&1; }
static int popcnt_vec(const uint64_t *v,int words){ int c=0; for(int i=0;i<words;i++) c+=__builtin_popcountll(v[i]); return c; }

// re-derive secret y (and x) exactly as triq_pke_keygen does, from the 16-byte dk seed
static void derive_secret(const uint8_t *dk_pke, uint64_t *y, uint64_t *x){
    triq_xof_ctx ctx={0}; xof_init(&ctx, dk_pke, SEED_BYTES);
    vect_sample_fixed_weight1(&ctx, y, PARAM_OMEGA);
    vect_sample_fixed_weight1(&ctx, x, PARAM_OMEGA);
}

// The oracle primitive: submit a crafted PKE ciphertext (u,v) and return the
// decoded message m' (16 bytes). This is what the re-encryption timing leaks a
// function of. We also (for instrumentation) return the true decode-error weight.
static void submit_decode(const uint64_t *u,const uint64_t *v,const uint8_t *dk_pke,
                          uint8_t *m_out, int *err_wt_out, const uint64_t *y_truth){
    ciphertext_pke_t c={0};
    memcpy(c.u, u, VEC_N_SIZE_BYTES);
    memcpy(c.v, v, VEC_N1N2_SIZE_BYTES);
    triq_pke_decrypt((uint64_t*)m_out, dk_pke, &c);
    if(err_wt_out){
        // recompute the pre-decode word  t = truncate(v - u*y)  and, given the
        // decoded m', the residual error weight wt(t - encode(m')).
        uint64_t uy[VEC_N_SIZE_64]={0}, t[VEC_N_SIZE_64]={0}, em[VEC_N_SIZE_64]={0};
        vect_mul(uy, y_truth, u); vect_truncate(uy);
        vect_add(t, v, uy, VEC_N1N2_SIZE_64);       // GF(2): add == sub
        code_encode(em, (const uint64_t*)m_out);
        uint64_t d[VEC_N_SIZE_64]={0}; vect_add(d, t, em, VEC_N1N2_SIZE_64);
        *err_wt_out = popcnt_vec(d, VEC_N1N2_SIZE_64);
    }
}

int main(int argc,char**argv){
    uint8_t ent[48]={1},per[48]={2}; prng_init(ent,per,48,48);
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    crypto_kem_keypair(pk,sk);
    const uint8_t *dk_pke = sk + PUBLIC_KEY_BYTES; // 16-byte seed
    uint64_t y[VEC_N_SIZE_64]={0}, x[VEC_N_SIZE_64]={0};
    derive_secret(dk_pke, y, x);
    int wy=popcnt_vec(y,VEC_N_SIZE_64), wx=popcnt_vec(x,VEC_N_SIZE_64);
    printf("ground truth: wt(y)=%d wt(x)=%d (expect %d)\n", wy, wx, PARAM_OMEGA);
    printf("first 10 support positions of y: ");
    for(int i=0,c=0;i<PARAM_N&&c<10;i++) if(get_bit(y,i)){printf("%d ",i);c++;} printf("\n\n");

    // Experiment A: v = 0, u = single monomial X^i  =>  pre-decode word = truncate(shift_i(y)).
    // Scan i, record decode-error weight and decoded m'. This tells us the code's
    // effective behaviour on a weight-67 shifted-y error and whether a boundary exists.
    uint64_t u[VEC_N_SIZE_64], v[VEC_N_SIZE_64]={0};
    uint8_t m[PARAM_SECURITY_BYTES];
    int probes = argc>1?atoi(argv[1]):16;
    printf("Experiment A: v=0, u=X^i (weight-1 u); pre-decode err = truncate(shift y by i)\n");
    int m_nonzero=0;
    for(int i=0;i<probes;i++){
        memset(u,0,sizeof u); set_bit(u,i);
        int ew; submit_decode(u,v,dk_pke,m,&ew,y);
        int mw=0; for(int b=0;b<PARAM_SECURITY_BYTES;b++) mw+=__builtin_popcount(m[b]);
        // how many of y's support land in truncated (shifted) region:
        printf("  i=%2d: decode_err_wt=%4d  m'wt=%3d  m'[0..3]=%02x%02x%02x%02x\n",
               i, ew, mw, m[0],m[1],m[2],m[3]);
        if(mw) m_nonzero++;
    }
    printf("\n(A) nonzero-m' count = %d/%d\n", m_nonzero, probes);

    // Experiment B: calibrate per-block RM radius. u=0, v = encode(m*) + k errors
    // confined to block 0 (coords [0,384)). Find largest k that still decodes to m*.
    // Then push errors across up to D blocks (one error each) to confirm RS corrects 13.
    printf("\nExperiment B: RM per-block radius (u=0, k errors in block 0)\n");
    uint8_t mstar[PARAM_SECURITY_BYTES]; for(int b=0;b<PARAM_SECURITY_BYTES;b++) mstar[b]=(uint8_t)(0xA5^b);
    uint64_t em[VEC_N_SIZE_64]={0}; code_encode(em,(const uint64_t*)mstar);
    memset(u,0,sizeof u);
    int last_ok=-1;
    for(int k=0;k<=200;k++){
        uint64_t vv[VEC_N_SIZE_64]; memcpy(vv,em,sizeof vv);
        for(int j=0;j<k;j++) vv[(j)>>6]^=(UINT64_C(1)<<((j)&63)); // flip bits 0..k-1 (block 0)
        submit_decode(u,vv,dk_pke,m,NULL,y);
        int ok = (memcmp(m,mstar,PARAM_SECURITY_BYTES)==0);
        if(ok) last_ok=k; else { printf("  block0: decodes to m* for k<=%d ; first failure at k=%d\n",last_ok,k); break; }
    }

    // Experiment B2: 1 error in each of the first D blocks (block size 384), scan D.
    printf("Experiment B2: 1 err/block across first D blocks (RS symbol-error tolerance)\n");
    int ERRB = argc>2?atoi(argv[2]):120; // errors per block (past RM radius to force a symbol error)
    printf("  (using %d errors/block to force each block to a wrong symbol)\n", ERRB);
    int last_ok2=-1;
    for(int D=0;D<=42;D++){
        uint64_t vv[VEC_N_SIZE_64]; memcpy(vv,em,sizeof vv);
        for(int j=0;j<D;j++){ int base=j*384; for(int t=0;t<ERRB;t++){int pos=base+t; vv[pos>>6]^=(UINT64_C(1)<<(pos&63));} }
        submit_decode(u,vv,dk_pke,m,NULL,y);
        int ok=(memcmp(m,mstar,PARAM_SECURITY_BYTES)==0);
        if(ok) last_ok2=D; else { printf("  decodes to m* for D<=%d blocks w/1 err ; first failure at D=%d\n",last_ok2,D); break; }
    }
    return 0;
}
