/* Step 5: cross-interoperability between the SUBMITTED NEV code and an
 * independent implementation written literally from the specification
 * (Algorithm 11 + Algorithm 15 + section 3.1 Noise2Pt).
 *
 * Compiled twice from the SAME tree, once without and once with
 * -DSPEC_F1 -DSPEC_F2 -DSPEC_F3, per -DPARAMS=1..12 and per hash backend.
 * Everything else (API, DRBG, packing, NTT, hashes) is shared, so any observed
 * incompatibility is caused by exactly the three code-vs-spec deviations.
 *
 * Three-phase file protocol (no symbol collisions, no shared address space):
 *   ./xinterop keys  <N> <keysfile>            : N deterministic (seed -> pk, sk)
 *   ./xinterop encap <keysfile> <encfile>      : for every pk, encapsulate with
 *                                                a seed derived from the record
 *                                                seed -> (ct, ss)
 *   ./xinterop decap <keysfile> <encfile>      : decapsulate every ct with the
 *                                                matching sk, compare ss, report
 *                                                every return code
 *
 * Pairing keys/decap from one binary with encap from the other gives the two
 * interop directions.  Pairing all three phases in one binary is the control.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "params.h"
#include "api.h"
#include "kat_test/drng.h"
#include "kat_test/KEM_AlgorithmInstance.h"

DRNG_ctx drng_algorithm; /* consumed by kat_test/rng.c's randombytes() */

#define SEEDLEN_B 64
#define PKB KEM_PUBLICKEYBYTES
#define SKB KEM_SECRETKEYBYTES
#define CTB KEM_CIPHERTEXTBYTES
#define SSB KEM_BYTES

#if defined(USE_SHA3)
#define BACKEND_ID 1
#else
#define BACKEND_ID 2
#endif
#if defined(SPEC_F1) || defined(SPEC_F2) || defined(SPEC_F3)
#define IMPL_TAG "speclit"
#else
#define IMPL_TAG "submitted"
#endif

typedef struct {
    uint32_t magic, params, pk_len, sk_len, ct_len, ss_len;
    uint32_t n, q, compress, seed_bytes, count, backend;
} hdr_t;

static void mkseed(unsigned char s[SEEDLEN_B], uint32_t i, unsigned char tag)
{
    memset(s, 0, SEEDLEN_B);
    memcpy(s, "NEV-SPECLIT-XOP-", 16);
    s[16] = tag;
    for (int k = 0; k < 4; k++) s[20 + k] = (unsigned char)(PARAMS >> (8 * k));
    for (int k = 0; k < 4; k++) s[32 + k] = (unsigned char)(i >> (8 * k));
    for (int k = 48; k < SEEDLEN_B; k++) s[k] = (unsigned char)(0x5a ^ k ^ (i & 0xff));
}

static void fillhdr(hdr_t *h, uint32_t N)
{
    memset(h, 0, sizeof *h);
    h->magic = 0x4e455632u; h->params = PARAMS;
    h->pk_len = PKB; h->sk_len = SKB; h->ct_len = CTB; h->ss_len = SSB;
    h->n = PARAM_N; h->q = PARAM_Q; h->compress = COMPRESS;
    h->seed_bytes = SEED_BYTES; h->count = N; h->backend = BACKEND_ID;
}

static int chkhdr(const hdr_t *h)
{
    return !(h->magic == 0x4e455632u && h->params == PARAMS && h->backend == BACKEND_ID &&
             h->pk_len == PKB && h->sk_len == SKB && h->ct_len == CTB && h->ss_len == SSB &&
             h->n == PARAM_N && h->q == PARAM_Q && h->compress == COMPRESS);
}

int main(int argc, char **argv)
{
    static unsigned char pk[PKB], sk[SKB], ct[CTB], ss[SSB], ss2[SSB];
    unsigned char seed[SEEDLEN_B];
    unsigned long long pl, sl, cl, ssl;
    hdr_t h, h2;
    FILE *f, *g;
    int rc;

    if (argc < 3) { fprintf(stderr, "usage: keys N file | encap keys enc | decap keys enc\n"); return 2; }

    if (!strcmp(argv[1], "keys")) {
        uint32_t N = (uint32_t)strtoul(argv[2], NULL, 10);
        if (argc < 4) return 2;
        f = fopen(argv[3], "wb"); if (!f) { perror("fopen"); return 2; }
        fillhdr(&h, N); fwrite(&h, sizeof h, 1, f);
        for (uint32_t i = 0; i < N; i++) {
            mkseed(seed, i, 'K');
            if (init_random_number(&drng_algorithm, seed, SEEDLEN_B)) return 3;
            rc = kem_keygen(pk, &pl, sk, &sl);
            if (rc || pl != PKB || sl != SKB) { fprintf(stderr, "keygen rc=%d\n", rc); return 3; }
            fwrite(seed, 1, SEEDLEN_B, f); fwrite(pk, 1, PKB, f); fwrite(sk, 1, SKB, f);
        }
        fclose(f);
        printf("KEYS impl=%s params=%d be=%d N=%u\n", IMPL_TAG, PARAMS, BACKEND_ID, N);
        return 0;
    }

    if (!strcmp(argv[1], "encap")) {
        if (argc < 4) return 2;
        f = fopen(argv[2], "rb"); if (!f) { perror("fopen keys"); return 2; }
        if (fread(&h, sizeof h, 1, f) != 1 || chkhdr(&h)) { fprintf(stderr, "bad keys hdr\n"); return 3; }
        g = fopen(argv[3], "wb"); if (!g) { perror("fopen enc"); return 2; }
        fillhdr(&h2, h.count); fwrite(&h2, sizeof h2, 1, g);
        for (uint32_t i = 0; i < h.count; i++) {
            if (fread(seed, 1, SEEDLEN_B, f) != SEEDLEN_B) { fprintf(stderr, "short\n"); return 3; }
            if (fread(pk, 1, PKB, f) != PKB) return 3;
            if (fread(sk, 1, SKB, f) != SKB) return 3;
            mkseed(seed, i, 'E');   /* encapsulator's own deterministic coins */
            if (init_random_number(&drng_algorithm, seed, SEEDLEN_B)) return 3;
            rc = kem_enc(pk, PKB, ss, &ssl, ct, &cl);
            if (rc || cl != CTB || ssl != SSB) { fprintf(stderr, "enc rc=%d\n", rc); return 3; }
            fwrite(ct, 1, CTB, g); fwrite(ss, 1, SSB, g);
        }
        fclose(f); fclose(g);
        printf("ENCAP impl=%s params=%d be=%d N=%u\n", IMPL_TAG, PARAMS, BACKEND_ID, h.count);
        return 0;
    }

    if (strcmp(argv[1], "decap")) { fprintf(stderr, "unknown mode\n"); return 2; }
    if (argc < 4) return 2;
    f = fopen(argv[2], "rb"); if (!f) { perror("fopen keys"); return 2; }
    g = fopen(argv[3], "rb"); if (!g) { perror("fopen enc"); return 2; }
    if (fread(&h, sizeof h, 1, f) != 1 || chkhdr(&h)) { fprintf(stderr, "bad keys hdr\n"); return 3; }
    if (fread(&h2, sizeof h2, 1, g) != 1 || chkhdr(&h2) || h2.count != h.count) {
        fprintf(stderr, "bad enc hdr\n"); return 3;
    }
    unsigned long n = 0, rc0 = 0, rcpos = 0, rcneg = 0, ss_ok = 0, ss_bad = 0;
    int rcmin = 1 << 30, rcmax = -(1 << 30);
    for (uint32_t i = 0; i < h.count; i++) {
        if (fread(seed, 1, SEEDLEN_B, f) != SEEDLEN_B) break;
        if (fread(pk, 1, PKB, f) != PKB) break;
        if (fread(sk, 1, SKB, f) != SKB) break;
        if (fread(ct, 1, CTB, g) != CTB) break;
        if (fread(ss, 1, SSB, g) != SSB) break;
        n++;
        memset(ss2, 0xA5, SSB);
        rc = kem_dec(sk, SKB, ct, CTB, ss2, &ssl);
        if (rc == 0) rc0++; else if (rc > 0) rcpos++; else rcneg++;
        if (rc < rcmin) rcmin = rc;
        if (rc > rcmax) rcmax = rc;
        if (rc == 0 && !memcmp(ss, ss2, SSB)) ss_ok++;
        else if (rc == 0) ss_bad++;
    }
    fclose(f); fclose(g);
    printf("DECAP impl=%s params=%-2d be=%d n=%lu rc0=%lu rc_pos=%lu rc_neg=%lu "
           "rc_range=[%d,%d] ss_agree=%lu ss_disagree_on_rc0=%lu\n",
           IMPL_TAG, PARAMS, BACKEND_ID, n, rc0, rcpos, rcneg, rcmin, rcmax, ss_ok, ss_bad);
    return (ss_ok == n) ? 0 : 1;
}
