/* Generic ICCS-KEM audit: roundtrip, single-bit ct malleability scan
 * (does a modified ct decapsulate to the SAME key?), decaps-with-wrong-sk,
 * random-ct decaps. Every tampered decaps runs in a forked child so that
 * crashes are counted instead of killing the audit.
 * Compile with -DHDR='"KEM_xxx.h"'.
 * usage: audit N_roundtrip maxbits(-1=all,0=none) N_randomct [byte,list] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "drng.h"
#include HDR
#ifndef NO_DRNG_DEF
DRNG_ctx drng_algorithm;
#endif
static unsigned long long kl;
/* returns: kem_dec return code, or 1000+sig if crashed; key in out */
static int safe_dec(unsigned char *sk, unsigned long long sl, unsigned char *ct, unsigned long long cl, unsigned char *out) {
  int fd[2]; if (pipe(fd)) return -9999;
  pid_t p = fork();
  if (p == 0) { close(fd[0]); unsigned long long c; unsigned char k[1024]; memset(k, 0, sizeof k);
    int r = kem_dec(sk, sl, ct, cl, k, &c); if (write(fd[1], k, kl) < 0) {} _exit(r & 0xff); }
  close(fd[1]); memset(out, 0, kl); ssize_t got = read(fd[0], out, kl); (void)got; close(fd[0]);
  int st; waitpid(p, &st, 0);
  if (WIFSIGNALED(st)) return 1000 + WTERMSIG(st);
  return (signed char)WEXITSTATUS(st);
}
int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  int N = argc > 1 ? atoi(argv[1]) : 20;
  long maxbits = argc > 2 ? atol(argv[2]) : -1;
  int R = argc > 3 ? atoi(argv[3]) : 0;
  char *lst = argc > 4 ? argv[4] : NULL;
  unsigned long long pl = kem_get_pk_len_bytes(), sl = kem_get_sk_len_bytes(),
                     cl = kem_get_ct_len_bytes(), a, b, c, d;
  kl = kem_get_ss_len_bytes();
  unsigned char *pk = malloc(pl), *sk = malloc(sl), *pk2 = malloc(pl), *sk2 = malloc(sl),
                *ct = malloc(cl), *ct2 = malloc(cl), *k1 = malloc(kl), *k2 = malloc(kl), *k3 = malloc(kl);
  unsigned char seed[64];
  for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(i * 7 + 1);
  init_random_number(&drng_algorithm, seed, 64);
  printf("pk=%llu sk=%llu ct=%llu ss=%llu\n", pl, sl, cl, kl);
  int fail = 0;
  for (int t = 0; t < N; t++) {
    if (kem_keygen(pk, &a, sk, &b)) { puts("keygen err"); return 1; }
    if (kem_enc(pk, a, k1, &c, ct, &d)) { puts("enc err"); return 1; }
    if (kem_dec(sk, b, ct, d, k2, &c)) { puts("dec err on honest ct"); fail++; continue; }
    if (memcmp(k1, k2, kl)) fail++;
  }
  printf("roundtrip: %d/%d mismatches\n", fail, N);
  kem_keygen(pk2, &a, sk2, &b);
  kem_keygen(pk, &a, sk, &b);
  kem_enc(pk, a, k1, &c, ct, &d);
  int r = safe_dec(sk2, b, ct, cl, k3);
  printf("decaps with OTHER sk: ret=%d%s same_key=%d\n", r, r >= 1000 ? " (CRASH)" : "", !memcmp(k1, k3, kl));
  long tot = (long)cl * 8, step = 1, same = 0, nz = 0, tried = 0, crash = 0;
  if (maxbits > 0 && maxbits < tot) step = tot / maxbits;
  long bl[256]; int nb = 0;
  if (lst) { char *q = lst; while (*q && nb < 256) { bl[nb++] = strtol(q, &q, 10); if (*q == ',') q++; } }
  if (maxbits != 0 || lst)
  for (long ii = 0; lst ? ii < nb * 8 : ii * step < tot; ii++) {
    long p = lst ? bl[ii / 8] * 8 + ii % 8 : ii * step;
    memcpy(ct2, ct, cl);
    ct2[p / 8] ^= (unsigned char)(1u << (p % 8));
    int rr = safe_dec(sk, b, ct2, cl, k3);
    tried++;
    if (rr >= 1000) { crash++; if (crash <= 5) printf("  CRASH (sig %d) for flipped bit: byte %ld bit %ld\n", rr - 1000, p / 8, p % 8); continue; }
    if (rr) nz++;
    if (rr == 0 && !memcmp(k1, k3, kl)) {
      same++;
      if (same <= 20) printf("  SAME KEY for flipped bit: byte %ld bit %ld\n", p / 8, p % 8);
    }
  }
  printf("bitflip scan: tried=%ld same_key=%ld nonzero_ret=%ld crashes=%ld\n", tried, same, nz, crash);
  srand(12345); int rc = 0, rnz = 0;
  for (int t = 0; t < R; t++) {
    for (unsigned long long i = 0; i < cl; i++) ct2[i] = rand() & 0xff;
    int rr = safe_dec(sk, b, ct2, cl, k3);
    if (rr >= 1000) rc++; else if (rr) rnz++;
  }
  if (R) printf("random ct: %d trials, crashes=%d nonzero_ret=%d\n", R, rc, rnz);
  return 0;
}
