# Key-recovery attack on Shuttle

A black-box EUF-CMA key-recovery (and universal-forgery) attack on the
**Shuttle** lattice signature scheme (ICCS NGCC round-1 submission; design paper
ePrint 2026/1991, "Towards Practical Iterative Rejection Sampling"). From the
public key and a batch of signatures on adversary-chosen messages, the attack
recovers the entire signing key and forges a signature on a fresh message that
the *unmodified* reference verifier accepts.

## Why it works (one paragraph)

Shuttle replaces the abort branch of iterative *rejection* sampling with a
*rejection-free* transition that always emits one of two shifted candidates.
Each step `R_transition` **sign-normalises** the secret shift `v_i = X^{j_i} s`
so that `<z, v_i> > 0` before adding `±v_i`. This makes the emitted sign
correlate with the state's projection onto the secret, injecting a
**secret-dependent second-order correlation** into the signature. Empirically the
correlation `E[<z, s X^j>^2 / ||s||^2]` is larger by a constant `kappa ≈ 2` when
`j` lies in the challenge support. A bilinear statistic over signatures,

```
  acc[i][k] = sum over signatures, over j in supp(c) of  z0[j] * (X^{-j} z_s[i])[k]
            -> kappa * s[i][k],
```

back-shifts each challenge position onto the secret and averages, recovering
`s` exactly once enough signatures are collected. The rest of the key (`e'`)
follows from the public relation `b = a_gen + A_gen * s (mod q)`.

This is a *design*-level flaw, not an implementation slip: the sign-normalisation
`t <= 0` rule is prescribed by the specification (see `irs.c` / paper §3). The
Rényi-divergence security argument bounds a per-step *marginal* relative error of
the output density and is blind to this cross-coordinate correlation.

## Threat model

EUF-CMA. The adversary has the public key and may query the honest signer (which
holds `sk`) on messages of its choice. It never reads `sk`. In this program the
recovery uses only: `pk` (hence `seedA` and the rounded `b`), the queried
signatures, and the public `sample_c`. The true secret is opened **only** in the
block marked `SCORING ONLY`, purely to report the exact-coefficient count.

## Layout

```
src/key_recovery.c   full key recovery + forgery (the attack)
src/leak_probe.c     measures the second-moment leakage (kappa) directly
Makefile             links the attack against the Shuttle reference impl
run_all.sh           reproduces 128/256/512
```

## Build & run

Point `REF` at a Shuttle reference-implementation source directory for the
matching security level (must contain the scheme sources incl. `ntt/<q>/`):

```
make MODE=128 REF=/path/to/Reference_Implementation/SHUTTLE-128
./key_recovery                 # default query budget; prints recovery + forgery
./leak_probe 20000 0           # prints the second-moment gap ~= kappa
```

or all three levels at once:

```
REFROOT=/path/to/Reference_Implementation ./run_all.sh
```

## Expected output (Shuttle-128, ~3.0e5 signatures)

```
=== Shuttle-128 key recovery ===
signature queries : 300000 ...
forgery on fresh message : ACCEPTED by reference verifier (universal forgery)
[scoring] s1 exact : 768/768 ...
[scoring] s1 FULLY RECOVERED (exact signing key)
```

## Notes

* The recovery of `s1` (the `l*n` MLWE secret coefficients) is exact and uses
  only public data; possessing `s1` and `pk` yields the complete signing key,
  hence universal forgery.
* `e'` is completed from the public (pk-rounded) `b`; with `alpha_b in {2,2,4}`
  it is recovered up to the public-key rounding, which the verifier tolerates
  because it uses the same rounded `b`.
* Signature counts are conservative; `s1` correlation converges well before the
  full budget (see the paper's convergence curve).
