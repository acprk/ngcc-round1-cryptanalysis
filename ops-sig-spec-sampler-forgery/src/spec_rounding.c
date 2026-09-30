/* OPS-SIG specification Algorithms 30 (Decompose) and 32 (UseHint), transcribed VERBATIM from
 * "Algorithm specifications v1.0", p.13-14.  Defines the real `decompose`/`use_hint` symbols so
 * they replace the reference ones (reference rounding.c compiled with -Ddecompose=decompose_REF
 * -Duse_hint=use_hint_REF).  `make_hint`/`power2round` are taken from the reference unchanged.
 *
 * The spec wraps the high-bits bucket count at ceil(q/alpha) (Alg.30 line 4, Alg.32 line 5)
 * where alpha = 2*gamma2.  For OPS alpha | (q-1), so the correct count is (q-1)/alpha; ceil(q/alpha)
 * is one larger and never merged, so the top bucket is not folded to 0 -> honest verification fails.
 */
#include <stdint.h>
#include "params.h"
#include "reduce.h"
#include "rounding.h"

#define ALPHA        (2*GAMMA2)
#define SPEC_M       ((Q + ALPHA - 1)/ALPHA)   /* ceil(q/alpha)  -- exactly as written in the spec */

int32_t decompose(int32_t *a0, int32_t a) {
  int64_t x = ((int64_t)a % Q + Q) % Q;               /* 1: a <- a mod+ q               */
  int32_t a1 = (int32_t)((x + GAMMA2) / ALPHA);       /* 3: a1 <- floor((a+gamma2)/alpha) */
  if (a1 == SPEC_M) a1 = 0;                            /* 4: if a1 = ceil(q/alpha) set 0  */
  int64_t r0 = x - (int64_t)a1 * ALPHA;               /* 5: a0 <- a - a1*alpha           */
  if (r0 > (Q-1)/2) r0 -= Q;                           /* 6                               */
  *a0 = (int32_t)r0; return a1;
}

int32_t use_hint(int32_t a, unsigned int hint) {
  int32_t a0, a1 = decompose(&a0, a);                  /* 1 */
  if (hint == 0) return a1;                            /* 2-3 */
  int32_t m = SPEC_M;                                  /* 5: m <- ceil(q/2gamma2)         */
  if (a0 > 0) return (a1 + 1) % m;                     /* 6-7 */
  else        return (a1 - 1 + m) % m;                 /* 8-9 */
}
