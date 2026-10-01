/* kem-34-1 pattern witness for MAMBA-Frost: a candidate FO message M is PUBLICLY testable from (pk, ct).
   check(pk, ct, M): re-run the submitted crypto_kem_enc with randomness (M || salt_from_ct); compare ct.
   Uses neither sk nor a decapsulation oracle. If check passes, the session key is the enc output ss. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "drng.h"
#include API_H
DRNG_ctx drng_algorithm;
static int forced = 0; static uint8_t forced_buf[CRYPTO_BYTES + 32];
int randombytes(unsigned char *out, unsigned long long len) {
    if (forced) { if (len != sizeof forced_buf) return 1; memcpy(out, forced_buf, len); return 0; }
    return get_random_number(&drng_algorithm, out, len * 8ULL);
}
static int check(const uint8_t *pk, const uint8_t *ct, const uint8_t *M, uint8_t *ss_out) {
    static uint8_t c2[CRYPTO_CIPHERTEXTBYTES];
    memcpy(forced_buf, M, CRYPTO_BYTES); memcpy(forced_buf + CRYPTO_BYTES, ct + CRYPTO_CIPHERTEXTBYTES - 32, 32);
    forced = 1; ENC(c2, ss_out, pk); forced = 0;
    return memcmp(c2, ct, CRYPTO_CIPHERTEXTBYTES) == 0;
}
int main(void) {
    uint8_t seed[64]; for (int i = 0; i < 64; i++) seed[i] = (uint8_t)(3 * i + 1);
    init_random_number(&drng_algorithm, seed, 64);
    static uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES], ct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t ss[CRYPTO_BYTES], ss2[CRYPTO_BYTES], M[CRYPTO_BYTES], salt[32];
    KEYPAIR(pk, sk);
    /* honest encapsulation; we record the M it drew only to have a known-true candidate (SCORING) */
    uint8_t snap[CRYPTO_BYTES + 32]; DRNG_ctx save = drng_algorithm;
    get_random_number(&drng_algorithm, snap, sizeof snap * 8ULL); drng_algorithm = save;
    ENC(ct, ss, pk);
    memcpy(M, snap, CRYPTO_BYTES); memcpy(salt, snap + CRYPTO_BYTES, 32);
    int salt_ok = memcmp(salt, ct + CRYPTO_CIPHERTEXTBYTES - 32, 32) == 0;
    int ok_true = check(pk, ct, M, ss2), ss_ok = memcmp(ss, ss2, CRYPTO_BYTES) == 0;
    uint8_t W[CRYPTO_BYTES]; memcpy(W, M, CRYPTO_BYTES); W[0] ^= 1;
    int ok_wrong = check(pk, ct, W, ss2);
    printf("%s: |M|=%d bits; salt public in ct: %s; check(true M)=%d, recovered ss==honest ss: %s; check(M^1)=%d\n",
           NAME, CRYPTO_BYTES * 8, salt_ok ? "yes" : "NO", ok_true, ss_ok ? "yes" : "NO", ok_wrong);
    return !(ok_true && ss_ok && !ok_wrong && salt_ok);
}
