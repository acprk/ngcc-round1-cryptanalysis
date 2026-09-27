/* oracle.c -- demonstrates that the Aigis-Enc+ reference decapsulation is a
 * decryption / plaintext-checking oracle (implementation-level IND-CCA break).
 *
 * The Fujisaki-Okamoto re-encryption check in kem.c:mkem_dec has no effect on
 * the returned shared secret: the CPA-decryption key is copied into ss BEFORE
 * verify() runs, and the corrective cmov() writes into a dead local buffer.
 * Hence for EVERY ciphertext ct (valid or not),
 *
 *        Decaps(sk, ct) == Hash2( owcpa_dec(ct) || H(pk) ),
 *
 * which is exactly the FO "real" key with the implicit-rejection branch never
 * taken. This program measures, on the UNMODIFIED reference sources:
 *
 *   (C) correctness on honest ciphertexts,
 *   (T) tampered-ciphertext behaviour  (same-key / different-key / rc!=0),
 *   (D) decryption-oracle fidelity: Decaps(ct') == Hash2(Dec(ct')||H(pk)),
 *   (P) plaintext-checking-oracle soundness (correct + wrong guesses).
 *
 * Only public data (pk, ct) and the decapsulation oracle mkem_dec are used;
 * owcpa_dec / owcpa_enc here play the role of the attacker's OFFLINE prediction
 * from pk (they need no secret beyond what the attacker computes itself for the
 * prediction of Hash2(m*||H(pk))). Lines marked [ground truth] read the secret
 * only to score, never to steer.
 *
 *   usage: ./oracle [trials]        (default 300)
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

/* Attacker's offline model of the returned key for a ciphertext whose
 * CPA-plaintext is 'm': K = Hash2( m || H(pk) ). */
static void predict_key(uint8_t *K, const uint8_t *m, const uint8_t *pk)
{
  uint8_t buf[2 * SEED_BYTES];
  uint8_t kr[2 * SEED_BYTES];
  memcpy(buf, m, SEED_BYTES);
  Hash(buf + SEED_BYTES, (uint8_t *)pk, PK_BYTES);
  Hash2(kr, buf, 2 * SEED_BYTES);
  memcpy(K, kr, SEED_BYTES);
}

int main(int argc, char **argv)
{
  int N = (argc > 1) ? atoi(argv[1]) : 300;

  static uint8_t pk[PK_BYTES], sk[SK_BYTES], ct[CT_BYTES];
  static uint8_t ss[SEED_BYTES], ssd[SEED_BYTES];

  int corr_fail = 0;                 /* (C) */
  int t_same = 0, t_diff = 0, t_rc = 0; /* (T) */
  int d_ok = 0, d_tot = 0;           /* (D) */
  int p_ok = 0, p_tot = 0;           /* (P) */

  srand(0xA1615);

  for (int t = 0; t < N; t++) {
    mkem_keygen(pk, sk);

    /* ---- (C) honest correctness ---- */
    mkem_enc(pk, ss, ct);
    if (mkem_dec(sk, ct, ssd) || memcmp(ss, ssd, SEED_BYTES)) corr_fail++;

    /* ---- (T) tamper one random ciphertext bit ---- */
    uint8_t ctT[CT_BYTES];
    memcpy(ctT, ct, CT_BYTES);
    size_t pos = rand() % CT_BYTES;
    ctT[pos] ^= (uint8_t)(1u << (rand() % 8));
    int rc = mkem_dec(sk, ctT, ssd);
    if (rc) t_rc++;
    else if (!memcmp(ss, ssd, SEED_BYTES)) t_same++;  /* BAD: FO check bypassed */
    else t_diff++;

    /* ---- (D) decryption-oracle fidelity on invalid ciphertexts ---- */
    uint8_t ctD[CT_BYTES];
    memcpy(ctD, ct, CT_BYTES);
    for (int j = 0; j < 8; j++)                        /* corrupt the v block */
      ctD[CT_POLYVEC_COMPRESSED_BYTES + (t * 7 + j) % POLY_COMPRESSED_BYTES] ^= 0xFF;
    mkem_dec(sk, ctD, ssd);
    uint8_t m2[SEED_BYTES], Kpred[SEED_BYTES];
    owcpa_dec(m2, ctD, sk);              /* [ground truth] = attacker's Dec model */
    predict_key(Kpred, m2, pk);
    d_tot++;
    if (!memcmp(Kpred, ssd, SEED_BYTES)) d_ok++;

    /* ---- (P) plaintext-checking oracle ---- */
    /* attacker forms a ciphertext for a chosen message m0 with chosen coins,
       then checks a guess m* by predicting Hash2(m*||H(pk)) and comparing with
       the decapsulation output. Correct guess must accept; wrong must reject. */
    uint8_t m0[SEED_BYTES], coins[SEED_BYTES], ctP[CT_BYTES], Kg[SEED_BYTES];
    for (int i = 0; i < SEED_BYTES; i++) { m0[i] = rand() & 0xff; coins[i] = rand() & 0xff; }
    owcpa_enc(ctP, m0, pk, coins);
    mkem_dec(sk, ctP, ssd);
    predict_key(Kg, m0, pk);                       /* guess m* = m0 (correct) */
    p_tot++; if (!memcmp(Kg, ssd, SEED_BYTES)) p_ok++;
    uint8_t mbad[SEED_BYTES]; memcpy(mbad, m0, SEED_BYTES); mbad[0] ^= 1;
    predict_key(Kg, mbad, pk);                     /* guess m* != m0 (wrong)  */
    p_tot++; if (memcmp(Kg, ssd, SEED_BYTES)) p_ok++;
  }

  printf("=== Aigis-Enc+ set PARAMS=%d  (pk=%d sk=%d ct=%d ss=%d) ===\n",
         PARAMS, PK_BYTES, SK_BYTES, CT_BYTES, SEED_BYTES);
  printf("(C) honest correctness      : %d/%d ok\n", N - corr_fail, N);
  printf("(T) tampered ct             : same_key(BAD)=%d  different=%d  rc!=0=%d  (of %d)\n",
         t_same, t_diff, t_rc, N);
  printf("(D) decryption-oracle match : %d/%d  Decaps(ct')==Hash2(Dec(ct')||H(pk))\n", d_ok, d_tot);
  printf("(P) PC-oracle soundness     : %d/%d  (correct-accept + wrong-reject)\n", p_ok, p_tot);
  if (d_ok == d_tot && p_ok == p_tot && corr_fail == 0)
    printf("VERDICT: decryption/PC oracle CONFIRMED (FO check inert) -- IND-CCA broken.\n");
  else
    printf("VERDICT: check failed -- inspect above.\n");
  return 0;
}
