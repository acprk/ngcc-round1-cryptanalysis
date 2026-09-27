#ifndef HARNESS_H
#define HARNESS_H
#include <stdint.h>
#include "params.h"
#include "poly.h"

/* attacker-side replicas of the (static) helpers inside nike.c so we can
 * (a) craft M1 from a target bp polynomial and (b) compute ground-truth v.
 * These MUST match nike.c exactly; verified against the oracle at runtime. */

void a_poly_dither(poly *r, const unsigned char *seed, unsigned char domain, unsigned int delta);
void a_poly_pack_bits(unsigned char *out, const poly *p, unsigned int bits);
/* build received=M1 bytes from mu, u-poly (raw p-domain coeffs), c-poly (2-bit) */
void a_encode_b(unsigned char *r, const unsigned char *mu, const poly *b, const poly *c);
/* given desired effective bp coefficients (signed, mod q) and mu, produce raw u_raw
 * (p_u-domain) closest to it, and write the *actually achieved* bp back. */
void a_bp_target_to_uraw(poly *u_raw, poly *bp_achieved, const poly *bp_target,
                         const unsigned char *mu);

#endif
