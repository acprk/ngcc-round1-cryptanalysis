/* recover.c -- concrete consequences of the dead FO check in Aigis-Enc+.
 *
 * Because Decaps returns Hash2(owcpa_dec(ct)||H(pk)) for EVERY ciphertext and
 * the implicit-rejection branch is dead code, the KEM is malleable and the
 * decapsulation output is a deterministic function of the CPA-plaintext only.
 * Two attacks follow, both against the UNMODIFIED reference sources:
 *
 *  (A) IND-CCA distinguisher / intercepted session-key recovery.
 *      A man-in-the-middle observes an honest ciphertext ct (session key ss)
 *      and wants ss. It flips one low bit of the c1 (u) block, giving ct' != ct
 *      whose CPA-plaintext is unchanged (the perturbation is far below the
 *      message-decoding margin). One decapsulation query on ct' returns exactly
 *      ss. This is a legal IND-CCA decapsulation query (ct' != challenge ct) and
 *      recovers the session key with no lattice work.
 *
 *  (B) Plaintext-checking-oracle key-mismatch primitive.
 *      For a captured ct and a candidate message m*, the attacker predicts
 *      K* = Hash2(m*||H(pk)) and checks Decaps(ct)==K*. This decides
 *      owcpa_dec(ct)==m* with no error, the primitive underlying standard
 *      chosen-ciphertext lattice key-recovery (Ravi et al., TCHES 2020).
 *
 * The true secret is read only in blocks marked [ground truth], purely to score.
 *
 *   usage: ./recover [trials]      (default 300)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "params.h"
#include "owcpa.h"
#include "hashkdf.h"

int mkem_keygen(uint8_t *pk, uint8_t *sk);
int mkem_enc(uint8_t *pk, uint8_t *ss, uint8_t *ct);
int mkem_dec(uint8_t *sk, uint8_t *ct, uint8_t *ss);

static void predict_key(uint8_t *K, const uint8_t *m, const uint8_t *pk)
{
  uint8_t buf[2 * SEED_BYTES], kr[2 * SEED_BYTES];
  memcpy(buf, m, SEED_BYTES);
  Hash(buf + SEED_BYTES, (uint8_t *)pk, PK_BYTES);
  Hash2(kr, buf, 2 * SEED_BYTES);
  memcpy(K, kr, SEED_BYTES);
}

int main(int argc, char **argv)
{
  int N = (argc > 1) ? atoi(argv[1]) : 300;

  static uint8_t pk[PK_BYTES], sk[SK_BYTES], ct[CT_BYTES];
  static uint8_t ss[SEED_BYTES], rec[SEED_BYTES];

  int a_ok = 0, a_neq = 0;      /* (A) session-key recoveries / ct' != ct   */
  int b_acc = 0, b_rej = 0;     /* (B) correct-accept / wrong-reject counts  */
  int queries_A = 0;

  srand(0x5EED1);

  for (int t = 0; t < N; t++) {
    mkem_keygen(pk, sk);
    mkem_enc(pk, ss, ct);              /* honest session; ss is the target    */

    /* ---- (A) malleate: flip low bit 0 of the first c1 byte ---- */
    uint8_t ctp[CT_BYTES];
    memcpy(ctp, ct, CT_BYTES);
    ctp[0] ^= 0x01;                    /* one u-coefficient LSB; below margin  */
    if (memcmp(ctp, ct, CT_BYTES)) a_neq++;
    mkem_dec(sk, ctp, rec);            /* single oracle query                  */
    queries_A++;
    if (!memcmp(ss, rec, SEED_BYTES)) a_ok++;   /* [ground truth] compare      */

    /* ---- (B) PC oracle on a captured (attacker-formed) ciphertext ---- */
    uint8_t m0[SEED_BYTES], coins[SEED_BYTES], ctb[CT_BYTES], K[SEED_BYTES], out[SEED_BYTES];
    for (int i = 0; i < SEED_BYTES; i++) { m0[i] = rand() & 0xff; coins[i] = rand() & 0xff; }
    owcpa_enc(ctb, m0, pk, coins);
    mkem_dec(sk, ctb, out);
    predict_key(K, m0, pk);            /* PCO(ct, m0)  -> expect accept        */
    if (!memcmp(K, out, SEED_BYTES)) b_acc++;
    uint8_t mbad[SEED_BYTES]; memcpy(mbad, m0, SEED_BYTES); mbad[SEED_BYTES - 1] ^= 0x80;
    predict_key(K, mbad, pk);          /* PCO(ct, mbad) -> expect reject       */
    if (memcmp(K, out, SEED_BYTES)) b_rej++;
  }

  printf("=== Aigis-Enc+ set PARAMS=%d  key-recovery consequences ===\n", PARAMS);
  printf("(A) intercepted session-key recovery : %d/%d recovered  (ct' != ct: %d/%d, %d query each)\n",
         a_ok, N, a_neq, N, 1);
  printf("(B) PC-oracle: correct-accept=%d/%d  wrong-reject=%d/%d\n", b_acc, N, b_rej, N);
  if (a_ok == N && a_neq == N && b_acc == N && b_rej == N)
    printf("VERDICT: 1-query session-key recovery + sound PC-oracle CONFIRMED.\n");
  else
    printf("VERDICT: partial -- inspect above (near-margin coefficient?).\n");
  (void)queries_A;
  return 0;
}
