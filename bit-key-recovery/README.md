# Key-recovery attack on BiT

A transcript-only key-recovery attack on the **BiT** (Bimodal Triangular) lattice
Fiat--Shamir signature (ICCS NGCC round-1 submission). From a batch of honest
signatures and the public key, the attack recovers the entire signing secret and
forges a signature that the *unmodified* reference verifier accepts.

## Why it works (one paragraph)

BiT releases a response `z1 = [z0, z_tail(L=3)]` with `z0 = y0 ± c` and
`z_tail[i] = y1[i] ± c·s0[i]`, where the two halves share **one** bimodal sign bit.
That shared sign is a sign-free bilinear cross-term between `z0` and `z_tail`: it is
invisible to the per-coordinate Rényi / rejection-correctness argument (the same blind
spot that breaks Shuttle), but it survives a bilinear average. Recovering the per-
signature sign `σ = sign(⟨z0, c⟩)` and accumulating
`acc[i][k] = Σ_sigs σ · Σ_{j∈supp(c)} c[j]·z_tail[i][(j+k) mod± N]`
converges to a **fixed, secret-independent negacyclic-convolution kernel `H`** applied
to the secret `s0`. Deconvolving by `H` returns `s0`:
`s0 = nifft( nfft(acc_victim) / H )`. The kernel is a public object, so the attacker
fits it on its **own** calibration keypair (known secret) and applies it to the victim.
A public-relation finisher `R = center_q(16·b1 − A·s0) = e − b0 ∈ [−8,9]` fixes any
residual coordinates; it is self-certifying (a single wrong `s0` coefficient randomises
`R` everywhere), so `R` in range at all 768 coordinates certifies the full key.

## Threat model and purity

EUF-CMA. The adversary has `pk` and a batch of honest signatures on random messages,
and may generate its own throwaway calibration keypairs (whose secrets it knows). The
recovery uses ONLY: `pk`, the public signature transcripts, and the attacker's own
calibration key/signatures. The victim secret (`key.bin`) is read ONLY inside
`deconv.py`'s `[SCORING]` block — audit with `grep -n 'SK-READ' src/deconv.py` (all
scoring) and `grep -n 'key.bin' src/deconv.py`.

## Layout

```
src/gen_fixed.c   victim honest-signature generator (dumps pk.bin/key.bin)
src/gen_cal.c     attacker's OWN calibration-key signature generator (dumps calkey.bin)
src/est2.c        shared-sign bilinear estimator (public transcripts only); "ctrl" mode = control
src/deconv.py     kernel fit on the calibration key + deconvolution + [SCORING] + control
src/forge.c       public-relation finisher + forgery vs the unmodified verifier
src/sign_agreement.c   diagnostic: P(sigma == beta) (instrumented ref copy, not the attack)
Makefile, run_all.sh
subsample_score.sh         recovery vs. #signatures from the stored 2M run
measure_sign_agreement.sh  builds the sign-agreement diagnostic in a temp dir
results/                   saved transcripts of the runs reported in RESULTS.md
```

## Build & run

Point `REF` at a BiT-128 reference-implementation source directory:

```
REF=/path/to/Reference_Implementation/BiT-128 ./run_all.sh
```

`deconv.py` needs numpy (set `PY=/path/to/python` if the default `python3` lacks it). The reference implementation is NOT bundled.

## Expected output

Transcript of a fresh end-to-end run with the defaults (1M victim + 1M calibration
signatures), saved as `results/run_all_1M_2026-09-26.log`:

```
[SCORING] s0_rec exact 768/768
[SCORING] direct estimator (acc/h0, no deconvolution) exact 450/768
[SCORING/CONTROL] no-shared-sign estimator: exact 236/768  corr=-0.0396
init consistency 768/768
sign rc=0  verify(correct msg)=0(0=ACCEPT)  verify(wrong msg)=-1(nonzero=REJECT)
RESULT: COMPLETE BREAK — forgery ACCEPTED by reference verifier
[SCORING] final s0 exact 768/768
```

Every run writes its full transcript to `run_all.log`. Measured numbers, and how each was
produced, are in `RESULTS.md`.

## Notes

* Parameters (BiT-128): n=256, q=26881, k=l=3, τ=30; secret s0 has k·n=768 coefficients.
* Recovery vs. victim signatures (calibration fixed at 1M; `subsample_score.sh`):
  0.5M → 488–492/768 (finisher cannot close); 1M → 768/768 directly (three independent
  samples); 2M → 766/768, closed to 768 by the 2-coordinate search (~19 s). Recovery is
  not monotone in N at fixed calibration size (2M < 1M).
* The direct estimator without deconvolution scores 450–501/768 at every N tried; it
  does not approach 768.
* The sign estimate σ = sgn⟨z0,c⟩ agrees with the true bimodal sign only with
  probability ≈0.937 (`measure_sign_agreement.sh`), not 1 − negl; the attack still works
  because the empirically fitted kernel H absorbs the attenuation.
* The control (`est2 ctrl`, independent random sign) collapses recovery to 236/768 =
  chance, confirming the signal is the shared-bimodal-sign design leak.
* Tested on one victim key and one calibration key (both fixed keygen seeds); that H
  transfers across keys is therefore shown for this key pair only.
* This is a scheme-level statistical break (same class as Shuttle), not an
  implementation bug. Fix: do not share one bimodal sign across `z0` and `z_tail`
  (use independent signs), or otherwise remove the bilinear cross-term.
