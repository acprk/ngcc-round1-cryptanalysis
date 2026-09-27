#include "harness.h"
#include "fips202.h"
#include <string.h>

/* copy of poly_dither from nike.c (must stay in sync) */
void a_poly_dither(poly *r, const unsigned char *seed, unsigned char domain, unsigned int delta)
{
  unsigned char extseed[NIKE_SEEDBYTES + 1];
  unsigned char buf[SHAKE128_RATE];
  uint64_t state[25];
  unsigned int mask = delta - 1;
  unsigned int pos = SHAKE128_RATE;
  int i;

  extseed[0] = domain;
  for(i=0;i<NIKE_SEEDBYTES;i++)
    extseed[i+1] = seed[i];

  shake128_absorb(state, extseed, sizeof(extseed));
  for(i=0;i<PARAM_N;i++)
  {
    if(pos > SHAKE128_RATE - 2)
    {
      shake128_squeezeblocks(buf, 1, state);
      pos = 0;
    }
    r->coeffs[i] = (uint16_t)((buf[pos] | ((uint16_t)buf[pos+1] << 8)) & mask);
    pos += 2;
  }
}

void a_poly_pack_bits(unsigned char *out, const poly *p, unsigned int bits)
{
  unsigned int acc = 0, accbits = 0, outpos = 0;
  unsigned int mask = (1u << bits) - 1u;
  unsigned int i;
  for(i=0;i<NIKE_PACKEDPOLYBYTES(bits);i++) out[i]=0;
  for(i=0;i<PARAM_N;i++){
    acc |= ((unsigned int)p->coeffs[i] & mask) << accbits;
    accbits += bits;
    while(accbits>=8){ out[outpos++]=(unsigned char)(acc&0xff); acc>>=8; accbits-=8; }
  }
  if(accbits) out[outpos]=(unsigned char)(acc&0xff);
}

void a_encode_b(unsigned char *r, const unsigned char *mu, const poly *b, const poly *c)
{
  int i;
  for(i=0;i<NIKE_SEEDBYTES;i++) r[i]=mu[i];
  a_poly_pack_bits(r + NIKE_SEEDBYTES, b, PARAM_T_U);
  for(i=0;i<NIKE_RECBYTES;i++)
    r[NIKE_SEEDBYTES+NIKE_UPOLYBYTES+i] =
        c->coeffs[4*i] | (c->coeffs[4*i+1]<<2) | (c->coeffs[4*i+2]<<4) | (c->coeffs[4*i+3]<<6);
}

/* responder computes bp = (u_raw << H_U) - du  (mod q). We pick u_raw in [0,P_U)
 * so that the achieved bp is as close as possible to bp_target. */
void a_bp_target_to_uraw(poly *u_raw, poly *bp_achieved, const poly *bp_target,
                         const unsigned char *mu)
{
  poly du;
  int i;
  a_poly_dither(&du, mu, 0xB0, PARAM_DELTA_U);
  for(i=0;i<PARAM_N;i++){
    int tgt = (int)bp_target->coeffs[i]; /* value in [0,q) */
    int d = du.coeffs[i];
    /* want (u<<H_U) - d ≡ tgt (mod q) -> u ≈ (tgt + d) / 2^H_U */
    int num = tgt + d;
    int u = (num + (1<<(PARAM_H_U-1))) >> PARAM_H_U; /* rounded */
    u &= (PARAM_P_U - 1);
    u_raw->coeffs[i] = (uint16_t)u;
    int bp = (((int)u << PARAM_H_U) - d) & (PARAM_Q - 1);
    bp_achieved->coeffs[i] = (uint16_t)bp;
  }
}
