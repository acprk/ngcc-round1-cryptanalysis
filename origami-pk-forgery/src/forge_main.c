#include <stdio.h>
#include <string.h>
#include <time.h>
#include "drng.h"
#include "auxfunc.h"
#include "origami.h"
#include "SIG_AlgorithmInstance.h"
DRNG_ctx drng_algorithm;
int origami_forge_pk_only(uint8_t *sig, const uint8_t *pk, const uint8_t *digest, size_t len_digest, const uint8_t *salt, uint32_t rnd);
int main(int argc, char **argv) {
    int trials = argc > 1 ? atoi(argv[1]) : 20, ok = 0;
    unsigned char nonce[64]; for (int i = 0; i < 64; i++) nonce[i] = (unsigned char)(i * 13 + time(NULL));
    init_random_number(&drng_algorithm, nonce, 64);
    for (int t = 0; t < trials; t++) {
        unsigned char pk[BYTES_PK], sk[BYTES_SK], sig[BYTES_SIGNATURE], dg[BYTES_DIGEST], salt[BYTES_SALT];
        unsigned long long pl, sl; char msg[64];
        sig_keygen(pk, &pl, sk, &sl);             /* honest key; sk is discarded */
        memset(sk, 0, sizeof sk);
        snprintf(msg, sizeof msg, "forged message #%d", t);
        pseudohash(BYTES_DIGEST * 8, (unsigned char *)msg, strlen(msg) * 8ULL, dg);
        for (int i = 0; i < BYTES_SALT; i++) salt[i] = (unsigned char)(t * 31 + i);
        clock_t c0 = clock();
        int rc = -1; for (uint32_t rr = 0; rr < 8 && rc != 0; rr++) rc = origami_forge_pk_only(sig, pk, dg, BYTES_DIGEST, salt, (uint32_t)t * 1000u + rr * 7919u + 1u);
        double ms = 1000.0 * (clock() - c0) / CLOCKS_PER_SEC;
        int v = sig_verify(pk, BYTES_PK, sig, BYTES_SIGNATURE, (unsigned char *)msg, strlen(msg));
        printf("trial %d forge_rc=%d verify=%d (%.2f ms)\n", t, rc, v, ms);
        if (rc == 0 && v == 0) ok++;
    }
    printf("%s: %d/%d pk-only forgeries accepted\n", "Origami", ok, trials);
    return 0;
}
