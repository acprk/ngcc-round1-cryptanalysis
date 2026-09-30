/* OPS-SIG specification Algorithm 6 (SampleInBall), transcribed VERBATIM from
 * "Algorithm specifications v1.0", p.8.  Defines the real `poly_challenge` symbol so it
 * replaces the (correct) reference one at link time; the reference poly.c is compiled with
 * -Dpoly_challenge=poly_challenge_REF so its definition is renamed and unused.
 *
 * Literal reading of lines 16-17 ("Swap idx[i],idx[j]" then "c_{idx[j]} <- s_t", i=n-tau+t):
 * after the swap idx[j] = old idx[i]; since idx[n-tau+t] is untouched by earlier steps
 * (all used i'<i, j'<=i'), old idx[i] = n-tau+t deterministically -> the tau signs land on
 * the FIXED public support {n-tau,...,n-1}.  Challenge space = 2^tau (signs only).
 */
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "poly.h"
#include "auxfunc.h"

#define SIB_BUFLEN 8192
void poly_challenge(poly *c, const uint8_t seed[CTILDEBYTES]) {
  static uint8_t buf[SIB_BUFLEN];
  int32_t idx[N];
  pseudoXOF((unsigned long long)SIB_BUFLEN*8ULL, seed, (unsigned long long)CTILDEBYTES*8ULL, buf); /* 1 */
  for (unsigned i = 0; i < N; i++) { c->coeffs[i] = 0; idx[i] = (int32_t)i; }                     /* 2 */
  unsigned pos = (TAU + 7)/8;                        /* 3: tau sign bits, LE bit order per byte */
  for (unsigned t = 0; t < TAU; t++) {
    unsigned i = N - TAU + t, j;                     /* 5 */
    for (;;) {                                       /* 6-15: multiplication range reduction */
      uint32_t x = (uint32_t)buf[pos] | ((uint32_t)buf[pos+1] << 8); pos += 2;
      uint32_t m = x * (i + 1);
      j = m >> 16;
      uint32_t lo = m & 0xFFFF, thr = 65536u % (i + 1);
      if (lo >= thr) break;
    }
    int32_t tmp = idx[i]; idx[i] = idx[j]; idx[j] = tmp;              /* 16: Swap idx[i],idx[j] */
    int32_t s = 1 - 2*(int32_t)((buf[t/8] >> (t%8)) & 1);
    c->coeffs[idx[j]] = s;                                            /* 17: c_{idx[j]} <- s_t  */
  }
}
