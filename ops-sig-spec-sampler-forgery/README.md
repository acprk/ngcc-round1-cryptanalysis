# OPS-SIG: public-key-only forgery of the specified verifier (fixed-support SampleInBall)

A **spec-conformance** break of **OPS-SIG** (ICCS NGCC round-1 lattice signature, `sign-17`). Two
independent defects make *any implementation built faithfully from the written specification* either
**universally forgeable** or **non-functional** — while the **shipped reference binary is correct and
KAT-consistent**. This is the sign-11-3 (FlexTree) / `chinith-em-misalignment` pattern: a spec ↔ code
discrepancy where the specification, not the submitted binary, is broken.

- **F1 (design/spec, forgery).** The specification's `SampleInBall` (Algorithm 6, p.8) places the τ
  challenge signs on a **fixed, public support** `{n−τ, …, n−1}`. The challenge space collapses from the
  claimed `log2(C(n,τ)·2^τ) ≈ 234 / 261 / 525` bits to **τ = 39 / 45 / 90** bits, and a
  **public-key-only** attacker forges a signature accepted by a spec-conformant verifier in `≈ 2^τ`
  hashes. Demonstrated end-to-end at a toy τ with correct-reject controls; real L1 = `2^39` (feasible).
- **F2 (design/spec, correctness).** The specification's `Decompose` / `UseHint` (Algorithms 30 & 32,
  p.13–14) wrap the high-bits bucket count at `⌈q/α⌉` instead of `(q−1)/α` (`α = 2γ2`). A
  spec-conformant implementation then **rejects its own honest signatures** (measured 7.5% / 31.5% /
  67.0% at L1/L3/L5).

Every number below is produced on this machine from the **unmodified** vendor reference; the reference
is never bundled here.

## Why F1 works (one paragraph)

OPS-SIG is a Dilithium/ML-DSA clone; a signature `(c̃, z, h)` is accepted iff, for
`c = SampleInBall(c̃)`, the verifier's recomputed `w1 = UseHint(Az − c·t1·2^d, h)` satisfies
`H(μ ‖ W1Encode(w1)) = c̃`. The only barrier to forgery is that hash: an attacker must land in the
challenge set. Spec Algorithm 6 lines 16–17 read `Swap idx[i], idx[j]` then `c_{idx[j]} ← s_t` with
`i = n−τ+t`. After the swap `idx[j] = old idx[i]`, and because every earlier step used `i′ < i` and
`j′ ≤ i′`, the slot `idx[n−τ+t]` is never touched before step `t`, so `old idx[i] = n−τ+t`
**deterministically**. Thus `c_{n−τ+t} ← s_t`: the support is the fixed block `{n−τ,…,n−1}` and the
challenge is just its τ signs — `2^τ` possibilities on a **public, known** support. The forger fixes a
short `z` and a target `c*` (all `+1` on that support), computes `w = Az − c*·t1·2^d` (the verifier's
own reconstruction), and grinds ≤ 30 hint bits until the recomputed `c̃` yields `c*`. Expected `2^τ`
hashes; no secret key, no signing query. The per-try cost is τ-independent, so real L1 (τ=39) costs
`2^39`, L3 (τ=45) `2^45`, L5 (τ=90) `2^90` — all far below the claimed 128/256/512-bit (2λ = 256/512/1024)
forgery target; L1 is essentially practical.

The submitted **reference** `poly_challenge` is *not* Algorithm 6 — it is the correct Dilithium sampler,
properly generalised to `n ∈ {512,1024}` (10-bit index, two 64-bit sign words). It samples a full-support
weight-τ challenge, so it **rejects** the forgery (control below). The specification and the code disagree.

## Threat model and purity

EUF-CMA, **zero signing queries**, public key only. `src/forge.c` calls `crypto_sign_keypair` solely to
obtain a public key to attack and then **zeroes the secret key** (`grep SK-ZERO`); nothing after that
reads the secret key. The forgery reads only `pk` and the message. `src/verify_ref.c` links the
**unmodified** reference verifier as an independent control.

## What is completed vs extrapolated

- **Completed (real parameters):** F1a the fixed-support collapse (exactly τ positions, each in every
  sample); F2 the honest-verification-failure rate. Both run at the reference's real τ / γ2.
- **Completed (scaled τ):** the full public-key-only forgery, accepted by the spec verifier, rejected on
  a different message and by the reference sampler. `TOYTAU=20` completes in ~30 s single-core;
  `TOYTAU=24` in ~15 min. The mechanism and per-try cost are τ-independent.
- **Extrapolated (real τ):** L1 forgery = `2^39` hashes (≈ 1 core-day at the measured ~56 µs/try on a
  few cores; not run to completion here), L3 `2^45`, L5 `2^90`. (Same "extrapolated per-guess cost"
  convention as `chinith-em-misalignment` and `facto-dsa-forgery`.)

## Run it

```
REF="/path/to/OPS_Digital_Signature_Algorithm/.../Reference_Implementation/OPSsig-128" ./run_all.sh
# options: TOYTAU=24 (larger completed forgery), SEED=<n>, CC=gcc
```

`REF` is an unmodified vendor reference **instance** directory (the one containing `sign.c`, `poly.c`,
`params.h`, …). Obtain it from the ICCS submission package; it is **not** redistributed here. The script
only *links* the reference and swaps a single function via the preprocessor
(`-Dpoly_challenge=poly_challenge_REF` renames the reference symbol so our spec version wins — no
reference file is edited). Point `REF` at `OPSsig-256` / `OPSsig-512` to see F1a/F2 at the other levels.

## Layout

```
src/spec_sampler.c   spec Algorithm 6 (SampleInBall), verbatim -> fixed support {n-tau..n-1}
src/spec_rounding.c  spec Algorithms 30/32 (Decompose/UseHint), verbatim -> ceil(q/alpha) wrap
src/dist_check.c     [F1a] report the support of the linked sampler (spec vs reference)
src/honest_fail.c    [F2 ] honest KeyGen/Sign/Verify failure rate (public loop, no attack)
src/forge.c          [F1b] public-key-only forgery vs the spec verifier (SK-ZERO after keygen)
src/verify_ref.c     [F1b] control: the unmodified reference verifier rejects the forgery
run_all.sh           builds against REF and runs F1a, F2, F1b end-to-end
results/             a captured run log
```

## Expected output (abridged, L1)

```
[F1a] spec Alg.6 : never-hit=473/512  max-freq=20000/20000  =>  FIXED SUPPORT, 2^39 challenges
      reference  : never-hit=0/512     chi2/df=0.9           =>  uniform full support (correct)
[F2 ] spec rounding : honest verify-FAILURES 7.45%     reference : 0.00%
[F1b] verify(forged, target msg) = 0  ACCEPT     verify(forged, other msg) = -1
      reference (shipped) verifier on the forged signature: verify = -1  REJECT
      RESULT: FORGERY CONFIRMED (public key only, no signing query)
```

## Severity

**A (spec, certificational).** No attack on the submitted binary (which stays a sound Dilithium clone);
but a specification-conformant implementation is universally forgeable (≈ `2^39` at L1, public-key-only)
and, separately, fails its own honest verification. Fix: state Algorithm 6 as the actual FIPS-204
SampleInBall (the `c[i]=c[j]; c[j]=sign` form the code already uses), and correct the `⌈q/α⌉ → (q−1)/α`
wrap in Algorithms 30/32.
