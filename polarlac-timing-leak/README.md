# PolarLAC-Light: a real but non-exploitable decapsulation timing leak (honest negative)

A study of **PolarLAC-Light** (ICCS NGCC round-1 submission, a compact module-lattice KEM in
the LAC lineage). The submission's specification states that decapsulation runs in **constant
time**. That claim is **false**: decapsulation time leaks the Fujisaki--Okamoto re-encryption
rejection count `R`, a public function of the decrypted message. **This is the real finding.**

**This is NOT a key recovery, and NOT an IND-CCA break.** Correcting an earlier and stronger
draft, we report that the timing leak **does not** yield the plaintext-checking (PC) oracle a
chosen-ciphertext key recovery would need. An end-to-end recovery driven by a *genuine timing*
oracle recovers **0/512** coefficients. The repository is named `polarlac-timing-leak`, not
`...-key-recovery`, for exactly this reason.

## What is true, and what is not

- **True (the finding).** Decapsulation is non-constant-time. The re-encryption sampler
  (`sample_screened_poly` in `pke.c`, four screened polynomials) loops a total number of times
  `R` that depends only on the re-encrypted message `m'` through the public seed `G(m')`. Adjacent
  `R` classes are separated by about **9k CPU cycles per extra rejection** (`R=4` near 169k,
  `R=5` near 178k, `R=6` near 188k; `rdtscp`+`lfence`, `taskset`-pinned). An `R`-bucket classifier
  (which `R` class a decapsulation is in) has only **0.4-0.9% error** at a min-of-15 measurement.
- **Not true (no exploit).** The oracle a key recovery needs is the **message-flip predicate**
  ("does the decrypted message differ from a fixed baseline by one bit?"). Realising *that* from
  the clock has **68-99% per-query error in the real setting**, and the end-to-end recovery driven
  by it gets **0/512**. The obstruction is structural (below).

## Why the timing oracle is blind (the structural obstruction)

The chosen-ciphertext probe a key recovery would use routes a 32-coefficient block of the secret
into the first polar node, a repetition **REP-32** node yielding one secret-dependent bit. Reading
that bit cleanly requires **all partner channels pinned to `hatm=0`**, which fixes the remaining
message bits to a single pattern. But that pattern gives **`R=4` for both** the reference message
and its one-bit flip, so the two are **timing-indistinguishable** and the oracle is blind. Trying
to engineer a distinguishing `R`-gap by flipping partner channels corrupts the REP node's sign,
and by the time enough partners flip to actually move `R` (through the SM3 avalanche in `G`), the
target block **stops decoding to a single bit**. The clean-bit requirement and the `R`-gap
requirement **cannot be met at once**.

## About the earlier "512/512"

An earlier draft reported a full 512/512 recovery. That result obtained its PC-oracle by **reading
the decrypted plaintext directly** (a `memcmp` on the plaintext plus an injected simulated-noise
knob) — **not from a clock**. The algebraic recovery machinery in this package (`src/attack.c`,
`src/finish.c`) does recover the full key **when handed such an idealised PC-oracle**, which is
what those programs use; but timing cannot supply that oracle, so the idealised recovery is **not**
a timing attack and is **not** claimed as a break. It is included only to show that the algebra is
sound and that the barrier is the oracle, not the linear algebra.

## Threat model and purity

Standard PC-oracle / timing side-channel model (as in Ravi et al., generic side-channel attacks on
CCA-secure lattice KEMs). The timing harnesses link the **unmodified** reference and recompute `R`
offline from the reference's own exported routines (`poly_generate_tenary`, `fft_within_bound_int16`),
so they never instrument the reference source. The true secret is read **only** to score results
(to label ground truth for the oracle-error measurement), never fed to the oracle.

## Layout

```
src/oracle_validate.c   ground-truth R range + cycles-vs-R separation + timing-equality oracle error
src/oracle_time.c       message-flip timing oracle (needs the 2-line rejection-counter patch below)
src/attack.c            algebraic block recovery -- runs ONLY under an idealised PC-oracle (NOT timing)
src/finish.c            public-relation enumeration finish + decryption check (idealised-oracle path)
src/intersect_multi.py  majority-vote intersection of several probe families
src/llr_table.h         precomputed channel LLR table
Makefile, run_all.sh
harnesses/reinvestigate/harness_time.c    real-timing R-class separation (no source instrumentation)
harnesses/reinvestigate/harness_oracle.c  the message-flip TIMING oracle: 68-99% per-query error
harnesses/scratch_canary/sweep.c          canary-freedom vs probe-cleanliness trade-off; EXACT-R oracle-error ceiling
harnesses/scratch_canary/canary_probe.c   search for a slow-canary baseline (fails the clean-bit test)
harnesses/scratch_canary/diag.c           diagnostic of the REP-32 node decode vs partner flips
```

## Build & run

Point `REF` at a PolarLAC-Light reference-implementation source directory. The reference
implementation is **NOT** bundled; obtain it from the ICCS submission package.

```
REF=/path/to/Reference_Implementation/POLARLAC-Light ./run_all.sh
```

`run_all.sh` pins to an idle core and:
1. builds the re-investigation harnesses against the **unmodified** reference (they recompute `R`
   offline, so no source patch is needed);
2. measures the **real** timing leak (`R`-class separation ~9k cyc/rejection, `R`-bucket error);
3. runs the **message-flip timing oracle** end-to-end and reports its **68-99%** per-query error;
4. runs the canary/cleanliness `sweep` showing the EXACT-`R` oracle-error ceiling (why no timing
   oracle can work), i.e. the `0/512` conclusion.

## Expected output (honest negative)

```
[leak]   R over honest cts: {4,5,6,...}; cycles/rejection ~ 9k (R=4:~169k R=5:~178k R=6:~188k)
[leak]   R-bucket classifier error @min-of-15: ~0.4-0.9%      <- the leak is REAL
[oracle] message-flip TIMING oracle per-query error: 68-99%   <- the exploit is BLIND
[sweep]  clean-bit vs R-gap: no partner-flip count satisfies both (EXACT-R oracle also blind)
[result] end-to-end key recovery via GENUINE timing: 0/512    <- NOT a key recovery
```

## Timing instrumentation note

The re-investigation harnesses under `harnesses/` need **no** source patch. The legacy
`src/oracle_time.c` path does: to run it, add a global rejection counter to the reference sampler
`sample_screened_poly` in `pke.c`:

```c
unsigned long long g_reject_iters = 0;   /* file scope */
/* inside the for(;;) rejection loop, first line: */
g_reject_iters++;
```

## Fix for designers

Constant-iteration, `m'`-independent re-encryption sampling. That removes the non-constant-time
step; the leak is the only defect (there is no key-recovery exploit to close).

## Notes

* This is an **honest negative result**: a genuine specification violation (non-constant-time
  decapsulation) that we could **not** turn into a key recovery. Timing recovery is `0/512`.
* All timings on a 104-core / 251 GB machine, core-pinned with `taskset`.
