/* Subring-projection analysis harness for CheetahKEM (Cheetah128).
   Links the UNMODIFIED reference implementation (copied from src/, no edits).
   1) verifies that the scheme's NTT-based multiplication is negacyclic mod X^640+1
   2) runs the reference keygen/encaps/decaps and dumps (a, b, s, e) and ciphertext
      internals so that the sub-ring projection can be checked externally.
   The secret is dumped ONLY so that the attack's output can be checked against it. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "params.h"
#include "drng.h"
#include "auxfunc.h"
#include "poly.h"
#include "ntt.h"
#include "mod.h"
#include "KEM_Cheetah.h"

DRNG_ctx drng_algorithm;

static void pvec(FILE *f, const char *name, const int16_t *v, int n) {
    fprintf(f, "%s", name);
    for (int i = 0; i < n; i++) fprintf(f, " %d", v[i]);
    fprintf(f, "\n");
}
static void phex(FILE *f, const char *name, const unsigned char *v, int n) {
    fprintf(f, "%s ", name);
    for (int i = 0; i < n; i++) fprintf(f, "%02x", v[i]);
    fprintf(f, "\n");
}

/* schoolbook negacyclic multiplication mod (X^640+1), mod Q */
static void negacyclic(const int16_t *a, const int16_t *b, int16_t *c) {
    int32_t acc[2 * N];
    memset(acc, 0, sizeof(acc));
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            acc[i + j] = (acc[i + j] + (int32_t)a[i] * b[j]) % Q;
    for (int i = 0; i < N; i++)
        c[i] = standard_mod(acc[i] - acc[i + N]);
}

static int ring_test(void) {
    int16_t a[N], b[N], A[N], B[N], c1[N], c2[N];
    unsigned char rb[4 * N];
    get_random_number(&drng_algorithm, rb, 4 * N * 8);
    for (int i = 0; i < N; i++) {
        a[i] = ((rb[2 * i] << 8 | rb[2 * i + 1]) & 0x1fff) % Q;
        b[i] = ((rb[2 * N + 2 * i] << 8 | rb[2 * N + 2 * i + 1]) & 0x1fff) % Q;
    }
    memcpy(A, a, sizeof(a));
    memcpy(B, b, sizeof(b));
    ntt_640(A, NTT_FORWARD);
    ntt_640(B, NTT_FORWARD);
    for (int i = 0; i < N; i++) c1[i] = standard_mod((int32_t)A[i] * B[i]);
    ntt_640(c1, NTT_INVERSE);
    negacyclic(a, b, c2);
    int bad = 0;
    for (int i = 0; i < N; i++) if (c1[i] != c2[i]) bad++;
    printf("# ring_test: NTT-product vs schoolbook negacyclic mod (X^%d+1): mismatches=%d\n", N, bad);
    /* also test round trip */
    memcpy(A, a, sizeof(a));
    ntt_640(A, NTT_FORWARD); ntt_640(A, NTT_INVERSE);
    int bad2 = 0;
    for (int i = 0; i < N; i++) if (A[i] != a[i]) bad2++;
    printf("# ring_test: INTT(NTT(x))==x mismatches=%d\n", bad2);
    return bad || bad2;
}

int main(int argc, char **argv) {
    unsigned char nonce[64];
    for (int i = 0; i < 16; i++) memcpy(nonce + 4 * i, "dump", 4);
    if (argc > 1) nonce[0] = (unsigned char)atoi(argv[1]);
    init_random_number(&drng_algorithm, nonce, 64);

    if (ring_test()) { printf("# RING TEST FAILED\n"); }

    unsigned char pk[PUBLICKEY_BYTES], sk[SECRETKEY_BYTES];
    unsigned char ct[CIPHERTEXT_BYTES], ss[SHARED_KEY_BYTES], ss2[SHARED_KEY_BYTES];
    unsigned long long l1, l2, l3, l4;
    kem_keygen(pk, &l1, sk, &l2);
    kem_enc(pk, l1, ss, &l3, ct, &l4);
    kem_dec(sk, l2, ct, l4, ss2, &l3);
    printf("# ss match: %d\n", memcmp(ss, ss2, SHARED_KEY_BYTES) == 0);

    FILE *f = fopen(argc > 2 ? argv[2] : "dump.txt", "w");

    /* public matrix A (sampled directly in NTT domain), convert to coefficient domain */
    size_t xlen = CHEETAH_K * CHEETAH_K * N;
    int16_t Ahat[CHEETAH_K * CHEETAH_K * N], Acoef[CHEETAH_K * CHEETAH_K * N];
    unsigned char x[3 * CHEETAH_K * CHEETAH_K * N];
    pseudoXOF(3 * 8 * xlen, pk, SEED_BYTES * 8, x);
    sample_vector(x, Ahat, xlen);
    memcpy(Acoef, Ahat, sizeof(Ahat));
    for (int i = 0; i < CHEETAH_K * CHEETAH_K; i++) ntt_640(Acoef + i * N, NTT_INVERSE);

    /* secret key: stored in NTT domain */
    int16_t shat[CHEETAH_K * N], scoef[CHEETAH_K * N];
    decode_13bit_lsb(sk, CHEETAH_K * N, (uint16_t *)shat);
    memcpy(scoef, shat, sizeof(shat));
    for (int i = 0; i < CHEETAH_K; i++) ntt_640(scoef + i * N, NTT_INVERSE);

    /* public b, decompressed */
    int16_t bc[CHEETAH_K * N], btil[CHEETAH_K * N];
    decode_10bit_lsb(pk + SEED_BYTES, CHEETAH_K * N, bc);
    decompress(bc, CHEETAH_K * N, btil, QBITS - DB);

    /* ciphertext: u (compressed du) and v (128 coefficients, dv) */
    int16_t uc[CHEETAH_K * N], util[CHEETAH_K * N], vc[128], vtil[128];
    decode_10bit_lsb(ct, CHEETAH_K * N, uc);
    decompress(uc, CHEETAH_K * N, util, QBITS - DU);
    decode_4bit_lsb(ct + (CHEETAH_K * N) * DU / 8, SHARED_KEY_BYTES * 8, vc);
    decompress(vc, SHARED_KEY_BYTES * 8, vtil, QBITS - DV);

    /* recover the encapsulated message m by decrypting with the real secret
       (replicates indcpa_decrypt; used only as ground truth for the analysis) */
    int16_t uhat[CHEETAH_K * N];
    memcpy(uhat, util, sizeof(util));
    for (int i = 0; i < CHEETAH_K; i++) ntt_640(uhat + i * N, NTT_FORWARD);
    int16_t t[N], w[128];
    poly_vec_pwmul(uhat, shat, t);
    for (int i = 0; i < 128; i++) w[i] = vtil[i] - t[i];
    int16_t wc[128];
    memcpy(wc, w, sizeof(w));
    vector_mul_2(wc, 128); vector_centered_mod(wc, 128); vector_mod_2(wc, 128);
    unsigned char m[MSG_BYTES];
    encode_msg(wc, m);

    /* regenerate the encryption randomness r,e1,e2 from m (FO-derandomised) */
    unsigned char buf[MSG_BYTES + HASH_BYTES], kg[SHARED_KEY_BYTES + 3 * SEED_BYTES];
    memcpy(buf, m, MSG_BYTES);
    sm3hash(HASH_BYTES * 8, pk, PUBLICKEY_BYTES * 8, buf + MSG_BYTES);
    pseudoXOF((SHARED_KEY_BYTES + 3 * SEED_BYTES) * 8, buf, (MSG_BYTES + HASH_BYTES) * 8, kg);
    printf("# recovered-m gives matching ss: %d\n", memcmp(kg, ss, SHARED_KEY_BYTES) == 0);
    const unsigned char *coins = kg + SHARED_KEY_BYTES;
    int16_t r[CHEETAH_K * N], e1[CHEETAH_K * N], e2[N];
    size_t ylen = 2 * (CHEETAH_K * N) * ETA / 8;
    unsigned char y[2 * (CHEETAH_K * N) * ETA / 8];
    pseudoXOF(8 * ylen, coins, SEED_BYTES * 8, y);
    sample_noise_vector(y, r, CHEETAH_K * N);
    pseudoXOF(8 * ylen, coins + SEED_BYTES, SEED_BYTES * 8, y);
    sample_noise_vector(y, e1, CHEETAH_K * N);
    size_t wlen = 2 * N * ETA / 8;
    unsigned char wbuf[2 * N * ETA / 8];
    pseudoXOF(8 * wlen, coins + 2 * SEED_BYTES, SEED_BYTES * 8, wbuf);
    sample_noise_vector(wbuf, e2, N);

    fprintf(f, "N %d\nK %d\nQ %d\nETA %d\nDB %d\nDU %d\nDV %d\n", N, CHEETAH_K, Q, ETA, DB, DU, DV);
    phex(f, "pk", pk, PUBLICKEY_BYTES);
    phex(f, "ct", ct, CIPHERTEXT_BYTES);
    phex(f, "ss", ss, SHARED_KEY_BYTES);
    phex(f, "msg", m, MSG_BYTES);
    pvec(f, "a_coef", Acoef, CHEETAH_K * CHEETAH_K * N);
    pvec(f, "a_hat", Ahat, CHEETAH_K * CHEETAH_K * N);
    pvec(f, "s_coef", scoef, CHEETAH_K * N);
    pvec(f, "b_tilde", btil, CHEETAH_K * N);
    pvec(f, "u_tilde", util, CHEETAH_K * N);
    pvec(f, "v_tilde", vtil, 128);
    pvec(f, "r_coef", r, CHEETAH_K * N);
    pvec(f, "e1_coef", e1, CHEETAH_K * N);
    pvec(f, "e2_coef", e2, N);
    fclose(f);
    printf("# dumped\n");
    return 0;
}
