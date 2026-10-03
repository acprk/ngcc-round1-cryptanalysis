/* QUBE optimized implementation: unseeded-PRNG demonstration tool.
 * Linked against the UNMODIFIED optimized core (or, for the control, the core with
 * patches/seed-prng-from-drng.patch applied). Every mode first seeds the ICCS API DRNG
 * (drng_algorithm) from /dev/urandom, exactly as a correct integrator would. The point
 * of the demonstration is that the unmodified core never reads it.
 *
 *   keygen <pk> <sk>        crypto_kem_keypair
 *   enc    <pk> <ct> <ss>   crypto_kem_enc
 *   dec    <sk> <ct> <ss>   crypto_kem_dec
 *   katrec <KAT file>       attacker: fresh-process keypair, compare with record 0 PK,
 *                           decapsulate record 0 CT, compare with record 0 SS
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "drng.h"

DRNG_ctx drng_algorithm;
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

static unsigned char pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
static unsigned char ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES];

static void die(const char *m) { fprintf(stderr, "%s\n", m); exit(2); }
static void rd(const char *p, unsigned char *b, size_t n) {
    FILE *f = fopen(p, "rb"); if (!f || fread(b, 1, n, f) != n) die("read failed"); fclose(f);
}
static void wr(const char *p, const unsigned char *b, size_t n) {
    FILE *f = fopen(p, "wb"); if (!f || fwrite(b, 1, n, f) != n) die("write failed"); fclose(f);
}
static void seed_api_drng(void) {
    unsigned char e[64];
    rd("/dev/urandom", e, sizeof e);
    if (init_random_number(&drng_algorithm, e, sizeof e) != 0) die("init_random_number failed");
}
static int hex2bin(const char *h, unsigned char *o, size_t n) {
    for (size_t i = 0; i < n; i++) { unsigned v; if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1; o[i] = (unsigned char)v; }
    return 0;
}
static int field(FILE *f, const char *k, unsigned char *o, size_t n) {
    static char line[1 << 21]; size_t L = strlen(k); rewind(f);
    while (fgets(line, sizeof line, f)) if (!strncmp(line, k, L)) return hex2bin(line + L, o, n);
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2) die("usage: see source header");
    seed_api_drng();
    if (!strcmp(argv[1], "keygen") && argc == 4) {
        crypto_kem_keypair(pk, sk); wr(argv[2], pk, sizeof pk); wr(argv[3], sk, sizeof sk);
    } else if (!strcmp(argv[1], "enc") && argc == 5) {
        rd(argv[2], pk, sizeof pk); crypto_kem_enc(ct, ss, pk); wr(argv[3], ct, sizeof ct); wr(argv[4], ss, sizeof ss);
    } else if (!strcmp(argv[1], "dec") && argc == 5) {
        rd(argv[2], sk, sizeof sk); rd(argv[3], ct, sizeof ct); crypto_kem_dec(ss, ct, sk); wr(argv[4], ss, sizeof ss);
    } else if (!strcmp(argv[1], "katrec") && argc == 3) {
        static unsigned char kpk[CRYPTO_PUBLICKEYBYTES], kct[CRYPTO_CIPHERTEXTBYTES], kss[CRYPTO_BYTES];
        FILE *f = fopen(argv[2], "r"); if (!f) die("cannot open KAT file");
        if (field(f, "PK = ", kpk, sizeof kpk) || field(f, "CT = ", kct, sizeof kct) || field(f, "SS = ", kss, sizeof kss))
            die("KAT parse failed");
        crypto_kem_keypair(pk, sk);                 /* attacker: no secret input at all */
        crypto_kem_dec(ss, kct, sk);                /* decapsulate the victim's ciphertext */
        int a = !memcmp(pk, kpk, sizeof pk), b = !memcmp(ss, kss, sizeof ss);
        printf("  attacker pk == KAT record 0 PK : %s\n  recovered ss == KAT record 0 SS : %s\n", a ? "YES" : "NO", b ? "YES" : "NO");
        return (a && b) ? 0 : 1;
    } else die("bad arguments");
    return 0;
}
