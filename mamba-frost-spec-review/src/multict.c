/*
 * MAMBA-Frost (kem-20): scaled multi-ciphertext attack on the SPECIFIED (unsalted) Alg. 7.
 *
 * Spec Alg. 7 derives every encryption coin, including the ciphertext-dither seed mu (serialised
 * as the 32-byte "salt"), from G_FO(h_pk || M), so Encaps is deterministic in (pk, M). The
 * submitted kem.c instead reads (M, salt) from one randombytes() call. We model the spec simply
 * by supplying that randomness ourselves:  M := chosen,  salt := SHAKE(0xEE || h_pk || M).
 * The submitted crypto_kem_{keypair,enc,dec}_Frost128 are used UNMODIFIED.
 *
 * Scaling: M is restricted to MBITS = 16 bits (the real kappa_m = 128). T victim ciphertexts are
 * sent to one static key; the attacker sees only pk and the T ciphertexts, enumerates M,
 * re-encrypts, and looks the result up.  Expected work ~ 2^MBITS / (T+1).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "drng.h"
#include "Frost/src/api_frost128.h"
#include "common/sha3/fips202.h"

#define MBITS 16
#define T 64
#define BYTES_SALT 32

DRNG_ctx drng_algorithm;
static int enc_mode = 0;                 /* 0: keygen randomness from DRNG; 1: spec-Alg.7 coins */
static uint8_t cur_M[CRYPTO_BYTES], pkh[32];
static const uint8_t *fixed_salt = NULL;  /* salted mode: use this salt instead of H(h_pk||M) */

int randombytes(unsigned char *out, unsigned long long len)
{
    if (!enc_mode) return get_random_number(&drng_algorithm, out, len * 8ULL);
    /* crypto_kem_enc requests BYTES_MU + BYTES_SALT = CRYPTO_BYTES + 32 bytes: (M || salt) */
    if (len != CRYPTO_BYTES + BYTES_SALT) { fprintf(stderr, "unexpected request %llu\n", len); exit(2); }
    uint8_t in[1 + 32 + CRYPTO_BYTES];
    in[0] = 0xEE; memcpy(in + 1, pkh, 32); memcpy(in + 33, cur_M, CRYPTO_BYTES);
    memcpy(out, cur_M, CRYPTO_BYTES);
    if (fixed_salt) memcpy(out + CRYPTO_BYTES, fixed_salt, BYTES_SALT);      /* submitted code: salt given */
    else shake128(out + CRYPTO_BYTES, BYTES_SALT, in, sizeof in);   /* spec Alg. 7: salt = H(h_pk || M) */
    return 0;
}

static void spec_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, unsigned v)
{
    memset(cur_M, 0, sizeof cur_M); cur_M[0] = v & 255; cur_M[1] = (v >> 8) & 255;
    enc_mode = 1; crypto_kem_enc_Frost128(ct, ss, pk); enc_mode = 0;
}

int main(int argc, char **argv)
{
    uint8_t seed[64]; unsigned rs = argc > 1 ? (unsigned)atoi(argv[1]) : 1;
    for (int i = 0; i < 64; i++) seed[i] = (uint8_t)(i * 13 + 5 + rs);
    init_random_number(&drng_algorithm, seed, 64);

    static uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    static uint8_t ct[T][CRYPTO_CIPHERTEXTBYTES], ss[T][CRYPTO_BYTES], c2[CRYPTO_CIPHERTEXTBYTES];
    uint8_t s2[CRYPTO_BYTES], sd[CRYPTO_BYTES];
    crypto_kem_keypair_Frost128(pk, sk);
    shake128(pkh, 32, pk, CRYPTO_PUBLICKEYBYTES);

    int salted = argc > 2 && !strcmp(argv[2], "salted");
    static uint8_t salts[T][BYTES_SALT];
    /* victim: T encapsulations with secret random 16-bit M.
       default: spec Alg. 7 (salt = H(h_pk||M));  "salted": as the submitted code (fresh random salt) */
    srand(rs); unsigned secret[T];
    for (int i = 0; i < T; i++) {
        secret[i] = (unsigned)rand() & ((1u << MBITS) - 1);
        if (salted) { for (int j = 0; j < BYTES_SALT; j++) salts[i][j] = (uint8_t)rand(); fixed_salt = salts[i]; }
        spec_encaps(ct[i], ss[i], pk, secret[i]); fixed_salt = NULL;
        crypto_kem_dec_Frost128(sd, ct[i], sk);                 /* receiver side, not attacker: shows the ciphertexts are valid */
        if (memcmp(sd, ss[i], CRYPTO_BYTES)) { printf("victim decaps mismatch\n"); return 1; }
    }

    /* attacker: pk and ct[] only */
    long work = 0; int hit = -1; unsigned mv = 0;
    for (unsigned v = 0; v < (1u << MBITS) && hit < 0; v++) {
        if (!salted) {                       /* one encryption tests all T ciphertexts at once */
            spec_encaps(c2, s2, pk, v); work++;
            for (int i = 0; i < T; i++) if (!memcmp(c2, ct[i], CRYPTO_CIPHERTEXTBYTES)) { hit = i; mv = v; break; }
        } else {                             /* salts are public, but each guess must be re-encrypted per ciphertext */
            for (int i = 0; i < T && hit < 0; i++) {
                fixed_salt = ct[i] + CRYPTO_CIPHERTEXTBYTES - BYTES_SALT;
                spec_encaps(c2, s2, pk, v); work++; fixed_salt = NULL;
                if (!memcmp(c2, ct[i], CRYPTO_CIPHERTEXTBYTES)) { hit = i; mv = v; }
            }
        }
    }
    if (hit < 0) { printf("no hit\n"); return 1; }
    /* SCORING: ss[] and secret[] are the victim's ground truth, used only to report success */
    int other = (hit + 1) % T;
    printf("[%s] seed=%u T=%d MBITS=%d: hit ciphertext #%d after %ld encryptions (expected ~%d unsalted, ~%d salted); M=%u (true %u); "
           "session key recovered: %s; control (other ciphertext's key): %s\n",
           salted ? "salted (submitted code)" : "unsalted (spec Alg. 7)", rs, T, MBITS, hit, work, (1 << MBITS) / (T + 1), (int)((double)(1 << MBITS) * T / (T + 1)), mv, secret[hit],
           memcmp(s2, ss[hit], CRYPTO_BYTES) ? "NO" : "YES",
           memcmp(s2, ss[other], CRYPTO_BYTES) ? "differs (correct)" : "EQUAL?!");
    return memcmp(s2, ss[hit], CRYPTO_BYTES) != 0;
}
