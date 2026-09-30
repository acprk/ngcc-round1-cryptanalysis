/* cap512.c -- Rudraksh2-512 (kem-34): the secret key AND the session key are
 * deterministic functions of a single 256-bit SM3 chaining value.
 *
 *   noiseseed is exactly KEM_SYMBYTES = 64 bytes = one SM3 message block, so
 *      s, e  =  CBD( pseudoXOF(noiseseed || i || ctr) ),  pseudoXOF(x)=SM3(x||ctr)||...
 *   and every SM3 call over noiseseed shares the first-block chaining value
 *      CV = CF(IV, noiseseed)   (256 bits).
 *   Everything after the first block (i, ctr, padding, length) is a public constant,
 *   so s (hence the whole secret key) is a function of the 256-bit CV alone.
 *
 *   The KEM session key is capped the same way: in kem_enc,
 *      buf = m (64 B) || H(pk) (64 B),  hash_g = pseudoXOF(buf),
 *   and m is the first 64-byte block, so  K, seed_r = F( CF(IV,m), H(pk) ).
 *
 * This program runs the UNMODIFIED vendor kem_keygen / kem_enc, then rebuilds
 * (a) the secret-key bytes from the 32-byte CV of noiseseed, and
 * (b) the session key K from the 32-byte CV of m,
 * using nothing else. A byte-exact match on both proves the 256-bit cap.
 *
 * Attack cost (NOT run here): enumerate CV in {0,1}^256 -> ~2^256 classical,
 * Grover ~2^128, vs claimed classical 512 / quantum 256 for the 512 sets.
 *
 * Builds against a vendor Reference_Implementation/lwekem512 copied into the CWD.
 * Uses only the public API + the vendor's own SM3 core (auxfunc.c, #included so
 * the static compression function is reachable); redistributes no vendor code.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "auxfunc.c"        /* vendor SM3: sm3_bit_init, sm3_bit_compress (static), pseudoXOF */
#include "drng.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "cbd.h"
#include "symmetric.h"      /* hash_h / hash_g macros over pseudoXOF */
#include "KEM_lwekem512.h"

DRNG_ctx drng_algorithm;   /* the vendor library expects the caller to define+seed this */

/* Continue an SM3 hash from chaining value cv (after exactly one 64-byte block
 * has been absorbed), over `tlen` further message bytes, then finalise. Handles
 * a multi-block tail (e.g. hash_g's message is m||pkh = block0 + pkh + counter). */
static void sm3_cont(const unsigned int cv[8], const unsigned char *tail,
                     int tlen, unsigned char out[32]) {
    unsigned int d[8];
    memcpy(d, cv, 32);
    unsigned long long total_bits = (64ULL + (unsigned long long)tlen) * 8;
    int full = tlen / 64;
    for (int b = 0; b < full; b++) sm3_bit_compress(d, tail + 64 * b, 1);
    int rem = tlen - 64 * full;
    unsigned char blk[64];
    memset(blk, 0, 64);
    memcpy(blk, tail + 64 * full, rem);
    blk[rem] = 0x80;                                    /* SM3 padding */
    if (rem >= 56) { sm3_bit_compress(d, blk, 1); memset(blk, 0, 64); }
    for (int k = 0; k < 8; k++) blk[63 - k] = (unsigned char)(total_bits >> (8 * k));
    sm3_bit_compress(d, blk, 1);
    for (int k = 0; k < 8; k++) PUT32(out + 4 * k, d[k]);
}

/* Compress the first 64-byte block `seed` into its 256-bit chaining value. */
static void cv_of_block(const unsigned char seed[64], unsigned int cv[8]) {
    sm3_bit_init(cv);
    sm3_bit_compress(cv, seed, 1);
}

int main(int argc, char **argv) {
    if (KEM_SYMBYTES != 64) {
        printf("This demo targets the 512 sets (KEM_SYMBYTES=64); got %d\n", KEM_SYMBYTES);
        return 2;
    }
    /* Negative control: with --perturb we flip ONE bit of each 256-bit chaining
     * value before rebuilding. A correct experiment must then match 0/N, proving
     * the 50/50 result is not a tautology (e.g. a memcmp that always passes) but
     * genuinely pins the key to the exact 256-bit value. */
    int perturb = (argc > 1 && strcmp(argv[1], "--perturb") == 0);
    const int trials = 50;
    int sk_ok = 0, ss_ok = 0;
    unsigned char pk[KEM_PUBLICKEYBYTES], sk[KEM_SECRETKEYBYTES];
    unsigned char ss[KEM_SSBYTES], ct[KEM_CIPHERTEXTBYTES];
    unsigned long long l;

    for (int t = 0; t < trials; t++) {
        unsigned char seed[64];
        for (int j = 0; j < 64; j++) seed[j] = (unsigned char)(t * 37 + j * 11 + 1);

        /* ---- (a) SECRET KEY from the 256-bit CV of noiseseed ---- */
        init_random_number(&drng_algorithm, seed, 64);
        kem_keygen(pk, &l, sk, &l);                     /* genuine key pair */

        /* attacker-side bookkeeping: recompute noiseseed exactly as indcpa_keypair
         * does, collapse it to its 256-bit chaining value, then discard it. */
        unsigned char buf[2 * KEM_SYMBYTES];
        init_random_number(&drng_algorithm, seed, 64);
        get_random_number(&drng_algorithm, buf, KEM_SYMBYTES * 8);
        pseudoXOF(2 * KEM_SYMBYTES * 8, buf, KEM_SYMBYTES * 8, buf);  /* hash_g(buf,buf,64) */
        unsigned int cv_ns[8];
        cv_of_block(buf + KEM_SYMBYTES, cv_ns);         /* noiseseed = buf[64..127] */
        if (perturb) cv_ns[0] ^= 1u;                    /* negative control */
        memset(buf, 0, sizeof buf);                     /* only the 32-byte CV survives */

        /* rebuild s from CV alone, exactly as SampleCBDvec would */
        polyvec s;
        const int blen = KEM_ETA * KEM_N / 4;
        for (int i = 0; i < KEM_L; i++) {
            unsigned char prf[KEM_ETA * KEM_N / 4 + 32];
            for (unsigned c = 1; (int)(32 * (c - 1)) < blen; c++) {
                unsigned char tail[5] = { (unsigned char)i,
                                          (unsigned char)(c >> 24), (unsigned char)(c >> 16),
                                          (unsigned char)(c >> 8),  (unsigned char)c };
                sm3_cont(cv_ns, tail, 5, prf + 32 * (c - 1));
            }
            poly_cbd_eta(&s.vec[i], prf);
        }
        polyvec_ntt(&s);
        unsigned char skr[KEM_INDCPA_SECRETKEYBYTES];
        polyvec_tobytes(skr, &s);
        sk_ok += !memcmp(skr, sk, KEM_INDCPA_SECRETKEYBYTES);

        /* ---- (b) SESSION KEY from the 256-bit CV of m ---- */
        init_random_number(&drng_algorithm, seed, 64);  /* re-seed so the same m is drawn */
        kem_enc(pk, KEM_PUBLICKEYBYTES, ss, &l, ct, &l);/* genuine encapsulation, K in ss */

        /* recompute m the same way kem_enc does, collapse to CV(m), discard m */
        unsigned char m[KEM_SYMBYTES];
        init_random_number(&drng_algorithm, seed, 64);
        get_random_number(&drng_algorithm, m, KEM_SYMBYTES * 8);
        unsigned int cv_m[8];
        cv_of_block(m, cv_m);
        if (perturb) cv_m[0] ^= 1u;                     /* negative control */
        memset(m, 0, sizeof m);                          /* only CV(m) survives */

        /* pkh = H(pk) is public; rebuild kr = F(CV(m), pkh) and take K = kr[0..SS) */
        unsigned char pkh[KEM_SYMBYTES];
        hash_h(pkh, pk, KEM_PUBLICKEYBYTES);
        unsigned char kr[2 * KEM_SYMBYTES];
        for (unsigned c = 1; (int)(32 * (c - 1)) < 2 * KEM_SYMBYTES; c++) {
            /* hash_g input is (m || pkh); block 0 = m (folded into cv_m),
             * remaining message bytes are pkh (64 B), then the XOF counter (4 B). */
            unsigned char tail[KEM_SYMBYTES + 4];
            memcpy(tail, pkh, KEM_SYMBYTES);
            tail[KEM_SYMBYTES + 0] = (unsigned char)(c >> 24);
            tail[KEM_SYMBYTES + 1] = (unsigned char)(c >> 16);
            tail[KEM_SYMBYTES + 2] = (unsigned char)(c >> 8);
            tail[KEM_SYMBYTES + 3] = (unsigned char)c;
            sm3_cont(cv_m, tail, KEM_SYMBYTES + 4, kr + 32 * (c - 1));
        }
        ss_ok += !memcmp(kr, ss, KEM_SSBYTES);
    }

    printf("Rudraksh2-512 secret key rebuilt from %s256-bit SM3 chaining value: %d/%d exact\n",
           perturb ? "1-bit-PERTURBED " : "", sk_ok, trials);
    printf("Rudraksh2-512 session key  rebuilt from %s256-bit SM3 chaining value: %d/%d exact\n",
           perturb ? "1-bit-PERTURBED " : "", ss_ok, trials);
    if (perturb) return (sk_ok == 0 && ss_ok == 0) ? 0 : 1;  /* control passes iff nothing matches */
    return (sk_ok == trials && ss_ok == trials) ? 0 : 1;
}
