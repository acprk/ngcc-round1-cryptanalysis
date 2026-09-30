/* cross.c -- Rudraksh2 cross-implementation interoperability probe.
 *
 *   ./cross enc <N> <file>   run genuine keygen+encaps N times, write (pk,sk,ct,ss)
 *   ./cross dec <file>       run genuine decaps on each record, count ss agreements
 *
 * Two independent builds of the SAME parameter set must agree: encapsulator's ss
 * == decapsulator's ss for a correctly-decrypting ciphertext. A build that
 * silently derives a different key (e.g. a different error-correction constant)
 * scores 0/N and every session falls through to implicit rejection.
 *
 * Deterministic seeds so `enc` output is reproducible and build-independent.
 * Uses only the public API. Redistributes no vendor code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include HDR

DRNG_ctx drng_algorithm;

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s enc N file | dec file\n", argv[0]); return 2; }
    unsigned long long pl = kem_get_pk_len_bytes(), sl = kem_get_sk_len_bytes(),
                       cl = kem_get_ct_len_bytes(), ssl = kem_get_ss_len_bytes(), t;
    unsigned char *pk = malloc(pl), *sk = malloc(sl), *ct = malloc(cl),
                  *ss = malloc(ssl), *ss2 = malloc(ssl);

    if (!strcmp(argv[1], "enc")) {
        int N = atoi(argv[2]);
        FILE *f = fopen(argv[3], "wb");
        if (!f) { perror("fopen"); return 2; }
        for (int i = 0; i < N; i++) {
            unsigned char seed[64];
            for (int j = 0; j < 64; j++) seed[j] = (unsigned char)(i * 131 + j * 7 + 1);
            init_random_number(&drng_algorithm, seed, 64);
            kem_keygen(pk, &t, sk, &t);
            kem_enc(pk, pl, ss, &t, ct, &t);
            fwrite(pk, 1, pl, f); fwrite(sk, 1, sl, f);
            fwrite(ct, 1, cl, f); fwrite(ss, 1, ssl, f);
        }
        fclose(f);
        return 0;
    }

    FILE *f = fopen(argv[2], "rb");
    if (!f) { perror("fopen"); return 2; }
    int n = 0, ok = 0;
    while (fread(pk, 1, pl, f) == pl) {
        if (fread(sk, 1, sl, f) != sl) break;
        if (fread(ct, 1, cl, f) != cl) break;
        if (fread(ss, 1, ssl, f) != ssl) break;
        kem_dec(sk, sl, ct, cl, ss2, &t);
        n++;
        ok += !memcmp(ss, ss2, ssl);
    }
    printf("decaps agree %d/%d\n", ok, n);
    return 0;
}
