// H2 witness: within-signature multi-target structure of the ReSolveD-alpha BAVC tree.
// Build inside a copy of a reference tree (see run.sh). Uses only the submitted code.
//
// 1. Honest keygen + sign (real signer code path, voleith_sign).
// 2. PUBLIC: parse sig, recompute (mu,s), decode chall3, recompute the hidden-path set and the
//    list of revealed nodes exactly as the verifier does.
// 3. ORACLE (validation only): regenerate the signer's tree and check that EVERY revealed node is
//    a public function F_{s,iv}(p) of its hidden parent p -- F in {TCCR(p), TCCR(p)^p, TCCR(p^c1)},
//    all under the same (s, iv).  => one enumeration over p' in {0,1}^lambda tests all T targets.
// 4. KEY RECOVERY from ONE hidden parent (= the value a successful search returns), using only
//    public data + that parent: hidden leaf -> check vs published hidden-leaf commitment ->
//    u_alpha -> u_0 = c_alpha ^ u_alpha -> w = d ^ u_0.
// 5. FORGERY: sign a fresh message with the recovered witness and a random coin key (no sk),
//    verify with the unmodified sig_verify; control with one flipped witness bit.
#define SIG_TESTS 1
#include "bavc.c"
#include "vole.c"
#include "voleith_impl.c"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "rsd.h"
#include <stdio.h>

DRNG_ctx drng_algorithm;

static int getb(const uint8_t* s, unsigned i) { return (s[i >> 3] >> (i & 7)) & 1; }
static void setb(uint8_t* s, unsigned i) { s[i >> 3] |= (uint8_t)(1u << (i & 7)); }

int main(int argc, char** argv) {
  unsigned nkeys = argc > 1 ? (unsigned)atoi(argv[1]) : 3;
  unsigned char nonce[64];
  for (int i = 0; i < 64; i++) nonce[i] = (unsigned char)(i * 13 + 5);
  init_random_number(&drng_algorithm, nonce, 64);

  const sig_paramset_t* P = sig_get_paramset(SETID);
  const unsigned lambda = P->csp, lb = lambda / 8, L = P->L, tau = P->tau;
  const unsigned ellhat = quicksilver_row_bits(P), ehb = ell_hat_bytes(P);
  const unsigned ell = P->lenwit, ellb = (ell + 7) / 8;
  unsigned long long pkl = sig_get_pk_len_bytes(), skl = sig_get_sk_len_bytes(), snl = sig_get_sn_len_bytes();
  printf("set lambda=%u tau=%u L=%u Topen=%u ell=%u sig=%llu\n", lambda, tau, L, P->T_open, ell, snl);

  int allok = 1;
  for (unsigned key = 0; key < nkeys; key++) {
    uint8_t *pk = malloc(pkl), *sk = malloc(skl), *sig = calloc(1, snl), *sig2 = calloc(1, snl);
    unsigned long long a = pkl, b = skl;
    sig_keygen(pk, &a, sk, &b);
    const unsigned in_sz = P->owf_input_size;
    const uint8_t* owf_input = sk;          // == pk[0:in_sz]
    const uint8_t* owf_key = sk + in_sz;
    uint8_t witness[1024] = {0};
    rsd_extend_witness(witness, owf_key, owf_input, P);
    uint8_t rho[64];
    get_random_number(&drng_algorithm, rho, lambda);
    uint8_t msg[32];
    memset(msg, 0xA0 + key, sizeof msg);
    voleith_sign(sig, msg, sizeof msg, owf_key, owf_input, pk + in_sz, witness, rho, lb, P);
    if (sig_verify(pk, a, sig, snl, msg, sizeof msg) != 0) { printf("honest sig rejected?!\n"); return 1; }

    // ---- 2. public parsing
    uint8_t mu[2 * MAX_CSP_BYTES], s[MAX_CSP_BYTES], iv[IV_SIZE];
    hash_mu_s(mu, s, pk, in_sz, pk + in_sz, P->owf_output_size, msg, sizeof msg, lambda);
    memcpy(iv, dsignature_iv(sig, P), IV_SIZE);
    uint16_t delta[MAX_TAU];
    if (!decode_all_chall_3(delta, dsignature_chall_3(sig, P), P)) { printf("decode fail\n"); return 1; }
    const uint8_t* decom = dsignature_decom_i(sig, P);
    const uint8_t* coms = decom;                  // tau hidden-leaf commitments, 2*lambda each
    const uint8_t* nodes = decom + 2 * tau * lb;  // revealed node seeds
    uint8_t* S = calloc((2 * L - 1 + 7) / 8, 1);
    unsigned hid_leaf[MAX_TAU];
    for (unsigned i = 0; i < tau; i++) {
      unsigned al = pos_in_tree(i, delta[i], P);
      hid_leaf[i] = al;
      setb(S, al);
      while (al > 0 && !getb(S, (al - 1) / 2)) { al = (al - 1) / 2; setb(S, al); }
    }
    unsigned T = 0, par[4096], chi[4096];
    for (int i = (int)L - 2; i >= 0; --i) {
      int l = getb(S, 2 * i + 1), r = getb(S, 2 * i + 2);
      if (l | r) setb(S, i);
      if (l ^ r) { par[T] = (unsigned)i; chi[T] = 2 * i + 1 + l; T++; }
    }

    // ---- 3. oracle check of the target structure (all T under the same (s, iv))
    uint8_t rootkey[MAX_CSP_BYTES], ivchk[IV_SIZE];
    hash_r_iv(rootkey, ivchk, owf_key, mu, rho, lb, lambda);
    uint8_t* tree = generate_seeds(rootkey, iv, s, P);
    unsigned nL = 0, nR = 0, nB = 0, bad = 0, pick = ~0u;
    uint8_t h[MAX_CSP_BYTES], t2[MAX_CSP_BYTES];
    for (unsigned t = 0; t < T; t++) {
      const uint8_t* p = NODE(tree, par[t], lb);
      const uint8_t* v = nodes + t * lb;
      unsigned id = par[t] + 1;
      if (id < L / 2) {
        tccr_hash(p, s, iv, h, lambda);
        if (chi[t] == 2 * par[t] + 1) { bad += memcmp(h, v, lb) != 0; nL++; }
        else { xor_u8_array(h, p, t2, lb); bad += memcmp(t2, v, lb) != 0; nR++; }
      } else {
        memcpy(t2, p, lb);
        if (chi[t] == 2 * par[t] + 2) t2[0] ^= 1;
        tccr_hash(t2, s, iv, h, lambda);
        bad += memcmp(h, v, lb) != 0; nB++;
        if (pick == ~0u) pick = t;
      }
    }
    printf("key %u: T=%u revealed nodes (upper-left %u, upper-right %u, bottom %u); relation failures=%u\n",
           key, T, nL, nR, nB, bad);

    // ---- 4. key recovery from ONE hidden parent p* (oracle stands in for the search hit)
    uint8_t pstar[MAX_CSP_BYTES];
    memcpy(pstar, NODE(tree, par[pick], lb), lb);
    unsigned hidden_child = 2 * par[pick] + 1 + (chi[pick] == 2 * par[pick] + 1);  // the other child
    memcpy(t2, pstar, lb);
    if (hidden_child == 2 * par[pick] + 2) t2[0] ^= 1;
    uint8_t sd_hid[MAX_CSP_BYTES];
    tccr_hash(t2, s, iv, sd_hid, lambda);   // leaf seed (LeafHash: sd = key)
    int alpha = -1;
    for (unsigned i = 0; i < tau; i++) if (hid_leaf[i] == hidden_child) alpha = (int)i;
    uint8_t com[2 * MAX_CSP_BYTES];
    prg_2_lambda(sd_hid, iv, 0, com, lambda);
    int com_ok = alpha >= 0 && memcmp(com, coms + alpha * 2 * lb, 2 * lb) == 0;
    printf("  hidden leaf of instance alpha=%d recovered; matches published commitment: %s\n", alpha,
           com_ok ? "YES" : "NO");
    // opened seeds from the verifier's own reconstruction
    bavc_rec_t rec;
    uint8_t hcom[2 * MAX_CSP_BYTES];
    rec.h = hcom;
    rec.s = malloc((L - tau) * lb);
    if (!bavc_reconstruct(&rec, decom, delta, iv, mu, s, P)) { printf("reconstruct fail\n"); return 1; }
    const uint8_t* sp = rec.s;
    for (int i = 0; i < alpha; i++) sp += (bavc_max_node_index(i, P->tau1, P->k) - 1) * lb;
    unsigned Na = bavc_max_node_index(alpha, P->tau1, P->k);
    uint8_t* sda = malloc(Na * lb);
    for (unsigned j = 0, q = 0; j < Na; j++) {
      if (j == delta[alpha]) memcpy(sda + j * lb, sd_hid, lb);
      else memcpy(sda + j * lb, sp + (q++) * lb, lb);
    }
    uint8_t* ua = calloc(1, ehb);
    uint8_t* vtmp = calloc(MAX_DEPTH, ehb);
    convert_to_vole(iv, sda, false, alpha, ehb, ua, vtmp, P);
    uint8_t* u0 = calloc(1, ehb);
    if (alpha == 0) memcpy(u0, ua, ehb);
    else xor_u8_array(ua, dsignature_c(sig, alpha - 1, P), u0, ehb);
    uint8_t wrec[1024] = {0};
    xor_u8_array(dsignature_d(sig, P), u0, wrec, ellb);
    if (ell % 8) { wrec[ellb - 1] &= (uint8_t)((1u << (ell % 8)) - 1); }
    uint8_t wtrue[1024] = {0};
    memcpy(wtrue, witness, ellb);
    if (ell % 8) { wtrue[ellb - 1] &= (uint8_t)((1u << (ell % 8)) - 1); }
    int wok = memcmp(wrec, wtrue, ellb) == 0;
    printf("  recovered witness (%u bits) equals signer's witness: %s\n", ell, wok ? "YES" : "NO");

    // ---- 5. fresh-message forgery with recovered witness, no secret key
    uint8_t fake_coin_key[MAX_CSP_BYTES], rho2[64], msg2[40];
    get_random_number(&drng_algorithm, fake_coin_key, lambda);
    get_random_number(&drng_algorithm, rho2, lambda);
    memset(msg2, 0x42, sizeof msg2);
    msg2[0] = (uint8_t)key;
    voleith_sign(sig2, msg2, sizeof msg2, fake_coin_key, pk, pk + in_sz, wrec, rho2, lb, P);
    int acc = sig_verify(pk, a, sig2, snl, msg2, sizeof msg2) == 0;
    wrec[0] ^= 1;
    voleith_sign(sig2, msg2, sizeof msg2, fake_coin_key, pk, pk + in_sz, wrec, rho2, lb, P);
    int ctl = sig_verify(pk, a, sig2, snl, msg2, sizeof msg2) == 0;
    printf("  forged fresh message accepted: %s; control (1 witness bit flipped) accepted: %s\n",
           acc ? "YES" : "NO", ctl ? "YES" : "NO");
    allok &= (bad == 0) && com_ok && wok && acc && !ctl;
    free(tree); free(S); free(rec.s); free(sda); free(ua); free(vtmp); free(u0);
    free(pk); free(sk); free(sig); free(sig2);
  }
  printf(allok ? "RESULT H2-STRUCTURE CONFIRMED\n" : "RESULT FAILED\n");
  return !allok;
}
