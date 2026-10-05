/* NSS-HQC (kem-26): the decryption vector y is a function of the 256-bit sub-seed seed_y alone.
 *
 * Built by run_all.sh against a COPY of the submitted Reference_Implementation/HQC-<level>
 * (this file #includes that copy's nss_hqc_core.c to reach its static helpers; nothing in the
 * submission is modified).
 *
 *   tool full <K>     unmodified code, full size. Victim keygen + encaps (API DRNG seeded from
 *                     /dev/urandom). [STRUCTURE CHECK, reads sk] seed_y = SHA3-512(seed_sk)[32..63]
 *                     is recomputed from the victim's seed_sk; the attacker-side routine
 *                     y_from_seed_y() (only the public sampler + the 32-byte seed_y) rebuilds y,
 *                     passes the public test wt(s + h*y) == w_sk, and decrypts the ciphertext to the
 *                     encapsulated session key. Then K random 32-byte candidates are tested as a
 *                     false-positive control (expected: 0 pass).
 *   tool search <b>   attack: given ONLY pk and ct, enumerate seed_y over its low b bits (high bits
 *                     zero), keep the candidate whose y passes the public test, decrypt, derive ss.
 *                     Against the scale-model build (-DDEMO_SEEDY_BITS=b) it must succeed; against
 *                     the unmodified build it must fail (control). The victim's sk is used ONLY for
 *                     scoring (SCORING: compare with the victim's own nss_hqc_dec).
 */
#include "nss_hqc_core.c"
#include <stdio.h>
#include <time.h>

DRNG_ctx drng_algorithm;

static void seed_drng_urandom(void)
{
    unsigned char s[48];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL || fread(s, 1, sizeof s, f) != sizeof s) { fprintf(stderr, "urandom\n"); exit(1); }
    fclose(f);
    init_random_number(&drng_algorithm, s, sizeof s);
}

static double now(void)
{
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec + 1e-9 * t.tv_nsec;
}

/* Attacker side: y from a 32-byte seed_y, exactly as keygen/pke_decrypt expand it. */
static void y_from_seed_y(uint8_t *y, const uint8_t sy[NSS_HQC_I_SEED_BYTES])
{
    xof_stream_t st = { 0 };
    memset(y, 0, NSS_HQC_N_BYTES);
    if (xof_stream_init(&st, sy, NSS_HQC_I_SEED_BYTES, 3u * NSS_HQC_W_SK + 4096u) != NSS_OK ||
        sample_fixed_weight1_stream(y, &st, NSS_HQC_W_SK) != NSS_OK) { fprintf(stderr, "sampler\n"); exit(1); }
    xof_stream_clear(&st);
}

/* Public test: s + h*y must be the weight-w_sk vector x. Uses only pk. */
static int public_test(const uint8_t *h, const uint8_t *pk, const uint8_t *y, uint8_t *t)
{
    const uint8_t *s = pk + NSS_HQC_PK_SEED_BYTES;
    ring_mul_by_sparse(t, h, y);
    for (uint32_t i = 0; i < NSS_HQC_N_BYTES; i++) t[i] ^= s[i];
    clear_unused_bits(t, NSS_HQC_N);
    return hamming_weight(t, NSS_HQC_N) == NSS_HQC_W_SK;
}

/* Decrypt with y alone (same steps as pke_decrypt), then ss = H_kappa(m || ct). Uses pk, ct, y. */
static int decaps_with_y(uint8_t *ss, const uint8_t *pk, const uint8_t *ct, const uint8_t *y)
{
    uint8_t *cw = calloc(NSS_HQC_NC_BYTES, 1), *d = calloc(NSS_HQC_NC_BYTES, 1), *t = calloc(NSS_HQC_N_BYTES, 1);
    uint8_t m[NSS_HQC_MSG_BYTES];
    const uint8_t *salt = ct + NSS_HQC_CT_BYTES;
    quant_decompress(cw, ct + NSS_HQC_N_BYTES);
    derive_dither(d, salt, pk);
    for (uint32_t i = 0; i < NSS_HQC_NC_BYTES; i++) cw[i] ^= d[i];
    ring_mul_by_sparse(t, ct, y);
    for (uint32_t i = 0; i < NSS_HQC_NC_BYTES; i++) cw[i] ^= t[i];
    clear_unused_bits(cw, NSS_HQC_NC);
    int r = nss_hqc_code_decode(m, cw);
    hash_kappa(ss, m, NSS_HQC_MSG_BYTES, ct);
    free(cw); free(d); free(t);
    return r;
}

static uint8_t pk[NSS_HQC_PK_BYTES], sk[NSS_HQC_SK_BYTES], ct[NSS_HQC_CT_FULL_BYTES];
static uint8_t ss_enc[NSS_HQC_SS_BYTES], ss_att[NSS_HQC_SS_BYTES], ss_dec[NSS_HQC_SS_BYTES];

static void victim(void)
{
    unsigned long long a, b;
    if (nss_hqc_keygen(pk, &a, sk, &b) || nss_hqc_enc(pk, a, ss_enc, &a, ct, &b)) { fprintf(stderr, "kem\n"); exit(1); }
    if (nss_hqc_dec(sk, NSS_HQC_SK_BYTES, ct, NSS_HQC_CT_FULL_BYTES, ss_dec, &a)) { fprintf(stderr, "dec\n"); exit(1); }
}

#define YN(c) ((c) ? "YES" : "NO")

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s full <K> | search <bits>\n", argv[0]); return 2; }
    seed_drng_urandom();
    victim();
    uint8_t *h = calloc(NSS_HQC_N_BYTES, 1), *y = calloc(NSS_HQC_N_BYTES, 1), *t = calloc(NSS_HQC_N_BYTES, 1);
    derive_h(h, pk);

    if (strcmp(argv[1], "full") == 0) {
        long K = atol(argv[2]);
        uint8_t sx[NSS_HQC_I_SEED_BYTES], sy[NSS_HQC_I_SEED_BYTES];
        derive_xy_seeds(sx, sy, sk);                     /* STRUCTURE CHECK: SK-READ (seed_sk) */
        double t0 = now();
        y_from_seed_y(y, sy);
        int pass = public_test(h, pk, y, t);
        double t1 = now();
        int dr = decaps_with_y(ss_att, pk, ct, y);
        printf("%s  |seed_sk|=%u bit  |seed_y|=%u bit  w_sk=%u n=%u\n", NSS_HQC_INSTANCE_NAME,
               8u * NSS_HQC_SEED_SK_BYTES, 8u * NSS_HQC_I_SEED_BYTES, NSS_HQC_W_SK, NSS_HQC_N);
        printf("  y rebuilt from seed_y alone: public test %s, decode=%d, ss(y-only)==encaps ss: %s, ==victim decaps: %s  (%.3f s per candidate)\n",
               pass ? "PASS" : "FAIL", dr, YN(!memcmp(ss_att, ss_enc, NSS_HQC_SS_BYTES)),
               YN(!memcmp(ss_att, ss_dec, NSS_HQC_SS_BYTES)), t1 - t0);
        long fp = 0;
        for (long k = 0; k < K; k++) {
            uint8_t c[NSS_HQC_I_SEED_BYTES];
            get_random_number(&drng_algorithm, c, 8u * sizeof c);
            y_from_seed_y(y, c);
            fp += public_test(h, pk, y, t);
        }
        printf("  control: %ld random seed_y candidates, %ld pass the public test\n", K, fp);
        return 0;
    }

    if (strcmp(argv[1], "search") == 0) {
        int bits = atoi(argv[2]);
        long found = -1, trials = 0;
        double t0 = now();
        /* ATTACK: from here on only pk, ct and the public sampler are used. */
        for (long cand = 0; cand < (1L << bits); cand++) {
            uint8_t sy[NSS_HQC_I_SEED_BYTES] = { 0 };
            for (int k = 0; k < 8; k++) sy[k] = (uint8_t)(cand >> (8 * k));
            y_from_seed_y(y, sy);
            trials++;
            if (public_test(h, pk, y, t)) { found = cand; break; }
        }
        double el = now() - t0;
#ifdef DEMO_SEEDY_BITS
        const char *build = "scale model (victim seed_y has DEMO_SEEDY_BITS bits)";
#else
        const char *build = "UNMODIFIED code (control)";
#endif
        if (found < 0) {
            printf("%s  [%s] search over 2^%d: NOT FOUND after %ld trials (%.1f s)\n",
                   NSS_HQC_INSTANCE_NAME, build, bits, trials, el);
            return 0;
        }
        int dr = decaps_with_y(ss_att, pk, ct, y);
        /* SCORING only: compare with the encapsulated key and the victim's own decapsulation. */
        printf("%s  [%s] seed_y found=%ld after %ld trials (%.1f s, %.3f s/trial) decode=%d  recovered ss==encaps ss: %s  ==victim decaps: %s\n",
               NSS_HQC_INSTANCE_NAME, build, found, trials, el, el / trials, dr,
               YN(!memcmp(ss_att, ss_enc, NSS_HQC_SS_BYTES)), YN(!memcmp(ss_att, ss_dec, NSS_HQC_SS_BYTES)));
        return 0;
    }
    return 2;
}
