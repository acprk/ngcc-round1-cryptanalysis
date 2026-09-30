/* Exhaustive single-bit flip sweep over sig bytes [lo,hi): prints every accepting mutation. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
DRNG_ctx drng_algorithm;
static unsigned char* rd(const char* d, const char* f, size_t* n) {
  char p[512]; snprintf(p, sizeof p, "%s/%s", d, f);
  FILE* fp = fopen(p, "rb"); if (!fp) { perror(p); exit(3); }
  fseek(fp, 0, SEEK_END); *n = (size_t)ftell(fp); fseek(fp, 0, SEEK_SET);
  unsigned char* b = malloc(*n + 1); if (fread(b, 1, *n, fp) != *n) exit(3); fclose(fp); return b;
}
int main(int argc, char** argv) {
  const char* dir = argv[1]; size_t pl, ml, sl;
  unsigned char *pk = rd(dir, "pk.bin", &pl), *msg = rd(dir, "msg.bin", &ml), *sig = rd(dir, argv[2], &sl);
  size_t lo = strtoul(argv[3], 0, 10), hi = strtoul(argv[4], 0, 10); if (hi > sl) hi = sl;
  unsigned char* m = malloc(sl);
  if (sig_verify(pk, pl, sig, sl, msg, ml) != 0) { printf("BASE_REJECT\n"); return 1; }
  long acc = 0, calls = 0; clock_t t0 = clock();
  for (size_t p = lo; p < hi; p++) for (int b = 0; b < 8; b++) {
    memcpy(m, sig, sl); m[p] ^= (unsigned char)(1u << b); calls++;
    if (sig_verify(pk, pl, m, sl, msg, ml) == 0) { acc++; printf("ACCEPT byte=%zu bit=%d\n", p, b); }
  }
  printf("RANGE [%zu,%zu) calls=%ld accepts=%ld cpu=%.1fs\n", lo, hi, calls, acc,
         (double)(clock() - t0) / CLOCKS_PER_SEC);
  return 0;
}
