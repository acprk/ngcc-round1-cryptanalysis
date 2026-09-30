# yuanyang-dsa-sampler-constant — YuanYang.DSA-512: signature mean is a linear function of the secret key

**Scope: implementation-level (severity B).** This package accompanies our Round-1 public comment on
YuanYang.DSA. It is *not* a design-level break and it does *not* contain a key recovery. It is
included in this repository, against its general policy of keeping only design-level packages,
because the comment cites a reproduction package and we want the numbers to be checkable.

## What we claim (and verified)

1. **A wrong constant.** In `fpr.h` of the `yuanyang-512` reference (and optimized) implementation,
   `fpr_yuanyang_inv_2sqr_large_sampler_sigma = 0x3ccc24a85` (43-bit fixed point) decodes to
   1/(2·(16η)²) with η = 1.026; the companion `fpr_yuanyang_large_sampler_sigma` decodes to 16.416 = 16η.
   The RCDT table (`sampler.c`, "sigma = 4*eta"), the specification (Table 2, 4η = 4.104) and
   `L = 4` in `sign.c` all say 4η. The `-1024` constants decode to exactly 4η. The zero-centred
   BerExp table was generated from the same 16η. The correct value is 0x3ccc24a84f.
2. **Broken 1-D sampler.** With the rejection almost always accepting, the zero-centred wide sampler
   outputs −z0 or z0+1 with equal probability: mean +0.458 instead of 0, variance 18.46 instead of
   16.84; the centred sampler largely ignores the fractional part of its centre (`logs/samp1d_orig.txt`
   vs `logs/samp1d_b2fixed.txt`).
3. **Non-zero, secret-dependent signature mean.** The perturbation inherits E[x] = 0.458·𝟙, so
   E[s] = (0.458/4)·Â·(𝟙,𝟙) + const, where Â is the rounded Gram root stored in the signing key.
   Measured on the unmodified reference (s1 from the released bytes, s2 = centerlift(m + h·s1) as the
   verifier computes it):
   - mean ≠ 0: χ² z ≈ 2300 at 2·10⁴ signatures (`logs/orig_k*.out`), 4.6·10⁴ at 4·10⁵.
   - secret dependence (`logs/regress_400k.txt`, N = 4·10⁵ per key): multiply the mean by (1−X)/2
     (since 𝟙·(1−X) = 2 in Z[X]/(X⁵¹²+1)), drop the constant coefficient, regress on the true a00:

     | mean of | regressed on | slope |
     |---|---|---|
     | key0, s1 | a00 of key0 | 0.102 ± 0.011 (z 9.6) |
     | key0, s1 | a00 of key7 | 0.010 ± 0.010 |
     | key7, s1 | a00 of key7 | 0.113 ± 0.010 (z 11.2) |
     | key7, s1 | a00 of key0 | −0.011 ± 0.013 |
     | key0 / key7, s2 | own a10+a11 | 0.128 ± 0.016 / 0.098 ± 0.012 (cross ≈ 0) |

     Predicted slope 0.458/4 = 0.1145. Residuals equal the sampling noise. The mean is therefore an
     unbiased estimator of a00 with coefficient error 432/√N (measured 0.65–0.70 at N = 4·10⁵).
4. **What a00 is.** With the covariance bug already public as ngcc.dev sign-34-1 (Σp built from
   B̂ᴴB̂), a00·ā00 = σ² − 1 − (f f̄ + g ḡ) exactly (σ = σ_sig/η; checked on the stored keys to 1e-5).
   f f̄ + g ḡ is the element that Fouque–Kirchner–Tibouchi–Wallet–Yu (EUROCRYPT 2020, ePrint
   2019/1180) show suffices, with the public key, to recover the whole secret.
5. **Fix-and-remeasure.** With the constant corrected (`patches/b2-large-sampler-constant.patch`) the
   mean test drops to z ≈ 2 (`logs/fix_k*.out`); with the covariance and Δ2 fixes as well, the
   secret-direction variance ratios become 1.000 ± 0.001 and 600/600 signatures verify
   (`logs/fd_k*.out`, `logs/full_k*.out`). The bug also raises the norm-rejection rate from ~2% to 15%
   per signature.

## What we do NOT claim

- **No key recovery was carried out.** Item 4 is a pointer to the literature, not an attack we ran.
- **The signature count is a simulation, not a measurement.** Using the measured noise, coefficient-wise
  rounding of f f̄ + g ḡ becomes error-free at about 3·10¹⁰ ≈ 2³⁵ signatures (20–24 of 512 coefficients
  still wrong at 10¹⁰; `logs/regress_400k.txt`). Smarter decoding (whitening by |a00(ζ)|, FKTWY's pruned
  tree search) may lower this; we did not try. 2³⁵ is inside the specification's "up to 2⁸⁰ signatures"
  security claim but corresponds to ~400 core-days of signing by the victim; we consider it a
  certificational, not a practical, issue.
- **Retraction of an earlier internal number.** An earlier internal write-up quoted regression slopes
  0.109 ± 0.008 / 0.116 ± 0.005 with cross-key slopes ≈ 0 ± 0.004 at N = 2·10⁴. That regression was
  done directly against Â·𝟙, whose lowest-frequency component dominates and is nearly collinear with the
  key-independent offset; the code is not in our artifacts and the tiny error bars do not survive the
  clean (1−X)/2 regression, which gives only ~2σ at N = 2·10⁴ (`logs/regress_20k.txt`). The 10σ result
  above needed 4·10⁵ signatures per key. Do not cite the earlier numbers.
- The `-1024` and `-2048` parameter sets are **not** affected by this constant (they have their own
  covariance issue, sign-34-1; `logs/r1024_k*.out`, `logs/r2048_k0.out`).
- The optimized implementation was checked statically only (identical constants); not executed.

## Contents

- `src/gapstat.c` — signs N messages through the reference API, reconstructs s2 as the verifier does,
  accumulates the mean and the per-frequency 2×2 covariance blocks; the secret key is read **only** to
  build scoring directions (marked `SCORING`).
- `src/samp1d.c` — 1-D sampler moments vs the exact discrete Gaussian.
- `src/dumpkey.c` — dumps f, g, F, G, û, Â of our own seeded test keys (scoring / regression input).
- `src/vcheck.c` — sign/verify round trip after the patches.
- `src/regress_mean.py` — the (1−X)/2 regression with cross-key controls and the signature-count simulation.
- `src/predict.py`, `src/which.py` — covariance model checks used for the sign-34-1 side of the story.
- `patches/` — the three one-line-class fixes (B2 constant, B1 covariance, B3 Δ2 exponent) as unified
  diffs against the vendor `yuanyang-512` sources. The B2 patch routes the zero-centred sampler through
  the generic sampler with centre 0 instead of the stale BerExp table; regenerating the table is the
  proper fix.
- `data/` — the two test keys (ours, from a fixed seed; **not** anyone's real key), the measured means at
  N = 2·10⁴ and 4·10⁵, and the covariance blocks after the B2 fix.
- `logs/` — real run logs behind every number above.
- `docs/comment.txt` — the public comment as submitted.

## Reproduce

```
REF=/path/to/YuanYang.DSA/Implementations/Reference_Implementation/yuanyang-512 ./run_all.sh 20000
REF=... ./run_all.sh 400000     # ~19 min per key single-core; needed for the ~10σ regression
```

The vendor sources are copied to `work/` and patched there; nothing under `$REF` is modified. No
vendor code is redistributed here. gcc, python3 + numpy.
