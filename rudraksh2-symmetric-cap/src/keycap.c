/* keycap.c -- Rudraksh2 (any set): the KEM session key is a function of the
 * lenK-byte message and the public key ALONE, independent of the ciphertext.
 *
 *   kem_enc:  (K, seed_r) = G( m || H(pk) ),  K = first KEM_SSBYTES bytes.
 *
 * So a generic key-recovery / IND attack is a search over m (8*lenK bits):
 * Grover message search costs about 2^(4*lenK) -> 2^64 (128 sets), 2^128 (256),
 * 2^128 (512, further capped by the 256-bit SM3 chaining value; see cap512.c),
 * versus the claimed quantum 80 / 128 / 256. The 128 sets' quantum-80 claim is
 * therefore not backed by a 128-bit message (this is depth-model dependent, the
 * AES-128 situation); the 512 sets fall short by a wide, unambiguous margin.
 *
 * This program runs the UNMODIFIED kem_enc to get (ct, K), recomputes the same
 * m, then rebuilds K from (m, pk) using only the public API pseudoXOF -- no sk,
 * no ct. A byte match proves K = G(m, H(pk)) and does not depend on ct.
 *
 * Redistributes no vendor code; builds against a vendor set copied into the CWD.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "drng.h"
#include "params.h"
#include "auxfunc.h"        /* pseudoXOF prototype */
#include "symmetric.h"      /* hash_h / hash_g macros */
#include HDR

DRNG_ctx drng_algorithm;

int main(void) {
    const int trials = 100;
    int ok = 0;
    unsigned long long pl = kem_get_pk_len_bytes(), sl = kem_get_sk_len_bytes(),
                       cl = kem_get_ct_len_bytes(), ssl = kem_get_ss_len_bytes(), t;
    unsigned char *pk = malloc(pl), *sk = malloc(sl), *ct = malloc(cl), *ss = malloc(ssl);

    for (int i = 0; i < trials; i++) {
        unsigned char seed[64];
        for (int j = 0; j < 64; j++) seed[j] = (unsigned char)(i * 53 + j * 3 + 7);

        init_random_number(&drng_algorithm, seed, 64);
        kem_keygen(pk, &t, sk, &t);
        init_random_number(&drng_algorithm, seed, 64); /* re-seed: kem_enc draws m first */
        unsigned char save[64]; memcpy(save, seed, 64);
        kem_enc(pk, pl, ss, &t, ct, &t);               /* genuine K in ss */

        /* recompute m the way kem_enc does (get_random_number, KEM_SYMBYTES bytes) */
        unsigned char m[KEM_SYMBYTES];
        init_random_number(&drng_algorithm, save, 64);
        get_random_number(&drng_algorithm, m, KEM_SYMBYTES * 8);

        /* rebuild K = first SSBYTES of G(m || H(pk)); uses only m and pk */
        unsigned char buf[2 * KEM_SYMBYTES], kr[2 * KEM_SYMBYTES];
        memcpy(buf, m, KEM_SYMBYTES);
        hash_h(buf + KEM_SYMBYTES, pk, pl);            /* H(pk), public */
        hash_g(kr, buf, 2 * KEM_SYMBYTES);             /* G(m || H(pk)) */
        ok += !memcmp(kr, ss, ssl);
    }
    printf("lenK=%dB: session key rebuilt from the message + public key alone "
           "(no sk, no ct): %d/%d exact  =>  Grover message search ~2^%d\n",
           KEM_SYMBYTES, ok, trials, 4 * KEM_SYMBYTES);
    return ok == trials ? 0 : 1;
}
