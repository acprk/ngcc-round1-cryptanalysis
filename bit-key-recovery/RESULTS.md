# BiT-128 attack — verified results (audit of 2026-09-26)

Every number below was re-measured on 2026-09-26 against the unmodified reference
implementation (`src/BIT_Bimodal_Triangular_distribution_base/.../Reference_Implementation/BiT-128`,
files untouched since 2026-06-30). Transcripts are in `results/`.

## Data sets

| data set | victim sigs | calibration sigs | where |
|---|---|---|---|
| A: fresh end-to-end `run_all.sh` | 1M (fresh) | 1M (fresh) | `results/run_all_1M_2026-09-26.log` (bins not kept) |
| B: stored run in this directory | 2M (`sig{A,B,C,D}.bin`, 500k each) | 1M (`cal*.bin`) | `results/subsample_2M_2026-09-26.log` |

Both use the same fixed-seed victim key and the same fixed-seed calibration key.
The attack has therefore been validated for **one key pair only**.

## Recovery vs. number of victim signatures (calibration fixed at 1M)

Subsamples of B are disjoint ("a" = first part, "b" = last part of every worker file).

| victim sigs | direct (acc/h0) | deconv exact | finisher | forgery |
|---|---|---|---|---|
| 0.5M (B a / B b) | 501 / 495 | 492 / 488 | fails (residual 276 / 280) | — |
| 1M (B a / B b / A) | 457 / 465 / 450 | **768 / 768 / 768** | not needed | ACCEPTED (x3) |
| 2M (B full) | 475 | 766 | 2-coord search closes it, ~19 s | ACCEPTED |

Control (independent random sign): 236/768 in A (corr −0.0396) and in B at 2M (corr −0.0238).

## Other measurements

* P(σ = β) = 0.9368 over 2×10^4 signatures (`measure_sign_agreement.sh`). σ is a
  noisy copy of the bimodal sign, not an exact one.
* Fitted kernel spectrum (from B's calibration): Re nfft(H) > 0 at every frequency,
  min|H|/max|H| = 0.047, max|Im|/mean Re = 0.28.
* Cost (run A, 104-core machine, 4 workers): victim gen 2:59, calibration gen 2:54,
  three est2 passes 80 s, deconv 0.14 s / 27 MB, forge < 0.01 s / < 1 MB (no residual);
  whole run 7:13.

## Corrections relative to the earlier claims

| earlier claim (README / paper) | measured |
|---|---|
| 2M → 767/768, finisher closes 1 | 766/768, 2-coord search closes 2 |
| 0.5M → 497/768 (residual 271) | 492 / 488 (residual 276 / 280) |
| direct estimator plateaus at ≈581 (later ≈510) | 450–501, no stable plateau |
| σ = β except with negligible probability | P(σ=β) = 0.937 |
| sig-gen ~13 min for 1M on 4 workers | ~3 min |
| deconv 3.2 s / 29.2 MB | 0.14 s / 27 MB |
| "all runs are single-core" | signature generation uses 4 parallel workers |
| nfft(H) real, well-conditioned | Re > 0, but Im up to 28 % and dynamic range ~21 |
| recovery monotone in N (√N scaling) | not monotone at fixed calibration (1M: 768, 2M: 766) |

What was never in doubt: `est2`/`deconv.py`/`forge` read only public data. The victim
key is read only in the scoring blocks, and the stored accumulators and `s0_rec.bin`
reproduce bit-for-bit from the stored signatures.

## Artifact fixes made in this audit

* `src/est2.c`: an unreadable input file now aborts the run. It used to be skipped
  silently, which produced a spurious 756/768 during the audit when files were deleted
  mid-read.
* `run_all.sh`: the control step no longer fails silently (`mv acc2.bin` on a file that
  `est2 ctrl` never writes). Workers are waited on by PID and a failing worker aborts the
  run. Stages are timestamped, the full transcript is saved to `run_all.log`, and the
  default is 1M victim signatures (the headline setting).
* `src/deconv.py`: also scores the direct estimator (acc/h0), so that baseline is reproducible.
* New: `subsample_score.sh`, `measure_sign_agreement.sh` + `src/sign_agreement.c`, `results/`.
