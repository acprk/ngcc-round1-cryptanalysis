/*
 * Driver: sEUF-CMA experiment against FlexTree using the vendor API only.
 *   1. keygen                                     (crypto_sign_keypair)
 *   2. signing oracle: N honest (M_i, sm_i)       (crypto_sign)
 *   3. SK-READ ends here: the secret key is zeroed before the attack phase.
 *   4. attacker, public data only: sigma_i' = maul(sigma_i), sigma_i' != sigma_i
 *   5. check sigma_i' || M_i with the vendor verifier (crypto_sign_open)
 *   6. controls: (a) honest sm_i accepted; (b) flipping one byte of the LAST
 *      USED auth node (just before the padding) is rejected; (c) mauled
 *      signature with a different message is rejected.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "params.h"
#include "drng.h"
#include "randombytes.h"

DRNG_ctx drng_algorithm;   /* vendor randombytes() draws from this (defined in KAT_SIG.c upstream) */

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m,
                unsigned long long mlen, const unsigned char *sk);
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm,
                     unsigned long long smlen, const unsigned char *pk);
long ft_maul(unsigned char *out, const unsigned char *in, const unsigned char *m,
             unsigned long long mlen, const unsigned char *pk, unsigned char fill);
int ft_public_auth_len(size_t *auth_len, const unsigned char *sig, const unsigned char *m,
                       unsigned long long mlen, const unsigned char *pk);
size_t ft_off_auth(void);

#define MLEN 33

int main(int argc, char **argv)
{
    int N = argc > 1 ? atoi(argv[1]) : 10;
    const char *label = argc > 2 ? argv[2] : "FlexTree";
    unsigned char seed[48];
    FILE *ur = fopen("/dev/urandom", "rb");
    if (!ur || fread(seed, 1, sizeof seed, ur) != sizeof seed) { perror("urandom"); return 2; }
    fclose(ur);
    init_random_number(&drng_algorithm, seed, sizeof seed);

    unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    const size_t SL = CRYPTO_BYTES + MLEN;
    unsigned char (*msg)[MLEN] = calloc(N, MLEN);
    unsigned char *sm  = calloc((size_t)N, SL);
    unsigned char *sm2 = calloc(1, SL);
    unsigned char *out = calloc(1, SL);
    unsigned long long smlen, outlen;

    crypto_sign_keypair(pk, sk);
    for (int i = 0; i < N; i++) {                                    /* signing oracle */
        randombytes(msg[i], MLEN);
        crypto_sign(sm + (size_t)i * SL, &smlen, msg[i], MLEN, sk);  /* SK-READ (honest signer) */
    }
    memset(sk, 0, sizeof sk);                                        /* no secret from here on */

    int padded = 0, forged = 0, ctrl_honest = 0, ctrl_boundary = 0, ctrl_msg = 0, errs = 0;
    long padsum = 0;
    for (int i = 0; i < N; i++) {
        unsigned char *s = sm + (size_t)i * SL;
        if (crypto_sign_open(out, &outlen, s, SL, pk) == 0) ctrl_honest++;

        long pad = ft_maul(sm2, s, msg[i], MLEN, pk, (unsigned char)(0xA5 + i));
        if (pad < 0) { errs++; continue; }
        if (pad == 0) { printf("  #%d: m'=mMAX, no padding (not mauled)\n", i); continue; }
        memcpy(sm2 + CRYPTO_BYTES, msg[i], MLEN);                    /* sm' = sigma' || M (same M) */
        padded++; padsum += pad;
        int differs = memcmp(sm2, s, SL) != 0;
        int ok = crypto_sign_open(out, &outlen, sm2, SL, pk) == 0
                 && outlen == MLEN && memcmp(out, msg[i], MLEN) == 0;
        if (differs && ok) forged++;

        /* control (b): corrupt the last USED auth node instead of the padding */
        size_t used; ft_public_auth_len(&used, s, msg[i], MLEN, pk);
        memcpy(sm2, s, SL);
        sm2[ft_off_auth() + used * SPX_N - 1] ^= 0x01;
        if (crypto_sign_open(out, &outlen, sm2, SL, pk) != 0) ctrl_boundary++;

        /* control (c): mauled signature, different message */
        ft_maul(sm2, s, msg[i], MLEN, pk, 0x5A);
        memcpy(sm2 + CRYPTO_BYTES, msg[i], MLEN);
        sm2[CRYPTO_BYTES] ^= 0x01;                                   /* first message byte */
        if (crypto_sign_open(out, &outlen, sm2, SL, pk) != 0) ctrl_msg++;

        printf("  #%d: m'=%zu/%d  padding=%ld B  sigma'!=sigma:%s  verify(sigma')=%s\n",
               i, used, SPX_PORS_FP_MAX_AUTH_NODES, pad, differs ? "yes" : "NO",
               ok ? "ACCEPT" : "reject");
    }
    printf("%s: %d/%d honest sigs have padding (avg %.1f B); %d/%d mauled sigs ACCEPTED by crypto_sign_open "
           "| controls: honest accepted %d/%d, boundary-node flip rejected %d/%d, wrong-msg rejected %d/%d%s\n",
           label, padded, N, padded ? (double)padsum / padded : 0.0, forged, padded,
           ctrl_honest, N, ctrl_boundary, padded, ctrl_msg, padded, errs ? " (ERRORS)" : "");
    return (forged == padded && padded > 0 && ctrl_honest == N && ctrl_boundary == padded
            && ctrl_msg == padded && !errs) ? 0 : 1;
}
