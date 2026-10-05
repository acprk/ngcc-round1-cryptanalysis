/* lx_struct.c — position-independence of the Lynxer BAVC seed tree, any parameter set.
 *
 * Compile inside a patched work/<set> copy with -DLX_PID=<LYNXER_xxx enum> (and -DLX_DEMO).
 * Captures the full seed tree and (tccr_s, iv) of a real signature via the read-only hook,
 * then recomputes every internal node's children with the submitted TCCR under the single
 * fixed (tccr_s, iv) — no node index enters. 0 mismatches ⇒ the tree is position-independent,
 * which is exactly what makes decom_I's T_open revealed nodes a multi-target set.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "SIG_AlgorithmInstance.h"
#include "instances.h"
#include "drng.h"
#include "tccr.h"

DRNG_ctx drng_algorithm;

uint8_t* lx_dbg_inst0_sd = NULL;   /* unused here but referenced by the hook */
unsigned int lx_dbg_inst0_n = 0;
uint8_t* lx_dbg_iv = NULL;
uint8_t* lx_dbg_nodes = NULL;
unsigned int lx_dbg_L = 0;
uint8_t* lx_dbg_tccr_s = NULL;

int main(void) {
  const sig_paramset_t* P = sig_get_paramset(LX_PID);
  const unsigned int lb = P->csp / 8;

  unsigned char seed[48];
  for (int i = 0; i < 48; i++) seed[i] = (unsigned char)(0x30 + i);
  init_random_number(&drng_algorithm, seed, 48);

  unsigned long long pklen, sklen, siglen;
  unsigned char* pk = malloc(sig_get_pk_len_bytes());
  unsigned char* sk = malloc(sig_get_sk_len_bytes());
  sig_keygen(pk, &pklen, sk, &sklen);

  uint8_t* inst0 = calloc((size_t)(1u << 16), lb);          /* generous upper bound on N0 */
  uint8_t ivb[32], ts[64];
  uint8_t* nodes = calloc((size_t)(1u << 16) * (size_t)P->tau + 64, lb);
  lx_dbg_inst0_sd = inst0; lx_dbg_iv = ivb; lx_dbg_nodes = nodes; lx_dbg_tccr_s = ts;

  unsigned char msg[32]; for (int i = 0; i < 32; i++) msg[i] = (unsigned char)i;
  unsigned char* sig = malloc(sig_get_sn_len_bytes());
  sig_sign(sk, sklen, msg, 32, sig, &siglen);

  unsigned int L = lx_dbg_L, half = L / 2, ok = 0, bad = 0;
  uint8_t l2[64], r2[64], tmp[64];
  for (unsigned int id = 1; id < L; ++id) {
    const uint8_t* parent = nodes + (size_t)(id - 1) * lb;
    const uint8_t* left   = nodes + (size_t)(2 * id - 1) * lb;
    const uint8_t* right  = nodes + (size_t)(2 * id) * lb;
    if (id < half) {
      tccr_hash(parent, ts, ivb, l2, P->csp);
      for (unsigned int i = 0; i < lb; i++) r2[i] = l2[i] ^ parent[i];
    } else {
      memcpy(tmp, parent, lb);
      tccr_hash(parent, ts, ivb, l2, P->csp);
      tmp[0] ^= 1;
      tccr_hash(tmp, ts, ivb, r2, P->csp);
    }
    if (memcmp(l2, left, lb) == 0 && memcmp(r2, right, lb) == 0) ok++; else bad++;
  }
  printf("csp=%u tau=%u T_open=%u L=%u  [pos-indep] internal=%u TCCR(parent)==children ok=%u bad=%u\n",
         P->csp, P->tau, P->T_open, L, ok + bad, ok, bad);
  return bad ? 1 : 0;
}
