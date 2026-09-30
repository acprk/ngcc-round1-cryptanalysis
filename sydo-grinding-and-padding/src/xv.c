/* SYDO cross-verifier harness (eval0930).
 *   gen  <outdir> <trial>        : keygen+sign (deterministic DRNG seed), write pk/sig/msg
 *   pad  <outdir>                : [ref only] measure free trailing bytes of bavc_open,
 *                                  write sig_mut.bin (all free bytes := 0xA5)
 *   ver  <outdir> <sigfile>      : verify <sigfile> against pk/msg, print 0/-1
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#ifdef SYDO_REF_LAYOUT
#include "internal.h"
#endif
DRNG_ctx drng_algorithm;

static unsigned char* rd(const char* d, const char* f, size_t* n) {
  char p[512]; snprintf(p, sizeof p, "%s/%s", d, f);
  FILE* fp = fopen(p, "rb"); if (!fp) { perror(p); exit(3); }
  fseek(fp, 0, SEEK_END); *n = (size_t)ftell(fp); fseek(fp, 0, SEEK_SET);
  unsigned char* b = malloc(*n + 1); if (fread(b, 1, *n, fp) != *n) exit(3); fclose(fp); return b;
}
static void wr(const char* d, const char* f, const unsigned char* b, size_t n) {
  char p[512]; snprintf(p, sizeof p, "%s/%s", d, f);
  FILE* fp = fopen(p, "wb"); if (!fp) { perror(p); exit(3); } fwrite(b, 1, n, fp); fclose(fp);
}

int main(int argc, char** argv) {
  if (argc < 3) return 2;
  const char* mode = argv[1]; const char* dir = argv[2];
  if (!strcmp(mode, "gen")) {
    int trial = argc > 3 ? atoi(argv[3]) : 0;
    unsigned char seed[64];
    for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(i * 7 + 3 + 31 * trial);
    init_random_number(&drng_algorithm, seed, 64);
    unsigned long long PK = sig_get_pk_len_bytes(), SK = sig_get_sk_len_bytes(), SN = sig_get_sn_len_bytes();
    unsigned char *pk = malloc(PK), *sk = malloc(SK), *sig = malloc(SN), msg[48];
    unsigned long long pl = PK, skl = SK, sl = SN;
    for (int i = 0; i < 48; i++) msg[i] = (unsigned char)(i * 13 + 1 + trial);
    if (sig_keygen(pk, &pl, sk, &skl)) { puts("keygen fail"); return 2; }
    if (sig_sign(sk, skl, msg, 48, sig, &sl)) { puts("sign fail"); return 2; }
    wr(dir, "pk.bin", pk, pl); wr(dir, "msg.bin", msg, 48); wr(dir, "sig.bin", sig, sl);
    printf("gen ok pk=%llu sig=%llu self_verify=%d\n", pl, sl, sig_verify(pk, pl, sig, sl, msg, 48));
    return 0;
  }
  size_t pl, ml, sl;
  unsigned char *pk = rd(dir, "pk.bin", &pl), *msg = rd(dir, "msg.bin", &ml);
  if (!strcmp(mode, "ver")) {
    unsigned char* sig = rd(dir, argv[3], &sl);
    int r = sig_verify(pk, pl, sig, sl, msg, ml);
    printf("verify(%s)=%d\n", argv[3], r);
    return 0;
  }
#ifdef SYDO_REF_LAYOUT
  if (!strcmp(mode, "pad")) {
    unsigned char* sig = rd(dir, "sig.bin", &sl);
    const sydo_ref_paramset_t* P = sydo_ref_get_paramset_by_name(ALGORITHM_INSTANCE);
    sydo_ref_signature_layout_t L = sydo_ref_signature_layout(P);
    size_t lo = L.bavc_open_offset, hi = L.bavc_open_offset + L.bavc_open_size;
    unsigned char* m = malloc(sl);
    /* walk backwards from end of bavc_open; byte is free iff flipping it keeps verify==0 */
    size_t freeb = 0;
    for (size_t p = hi; p-- > lo;) {
      memcpy(m, sig, sl); m[p] ^= 0xA5;
      if (sig_verify(pk, pl, m, sl, msg, ml) != 0) break;
      freeb++;
    }
    /* all free bytes mutated at once */
    memcpy(m, sig, sl);
    int zeros = 1;
    for (size_t p = hi - freeb; p < hi; p++) { if (sig[p]) zeros = 0; m[p] = 0xA5; }
    int r = sig_verify(pk, pl, m, sl, msg, ml);
    wr(dir, "sig_mut.bin", m, sl);
    printf("bavc_open=[%zu,%zu) free_tail_bytes=%zu (orig all-zero=%d) mutated_all_free -> ref_verify=%d\n",
           lo, hi, freeb, zeros, r);
    return 0;
  }
#endif
  return 2;
}
