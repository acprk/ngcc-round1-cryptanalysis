# nev-conformance-and-timing — NEV (kem-25): a plaintext-dependent timing channel, an unattainable published DFR, and a spec-that-can't-reproduce-its-own-KATs

**One-line claim.** NEV is **not broken** (no key recovery, no IND-CCA break, no parameter set below
its claimed level), but three things are wrong and each is reproduced here from vendor sources:
a **measured plaintext-dependent timing channel** in `ternary3` that survives under the spec's own
SHA3 (**CT-1**, Medium, on the recommended set **R3**); the **NEV-C2 published DFR (2^-162) is below
a rigorous lower bound (2^-152.72)**, i.e. **unattainable** (**F-0**, Medium — but it does **not**
breach any threshold, see below); and an independent implementation written from the specification
**reproduces none of the 12 shipped test vectors** and, on **R1 and D1 only**, fails to interoperate
(**F-1/F-2/F-3**, Low, conformance).

This package backs a possible public comment on the NEV forum thread (ngcc.dev `kem-25`, which as of
2026-09-30 publishes no finding and whose forum thread has zero comments). It contains **no key
recovery** and nothing design-breaking. `break_score` stays **1**.

## Scope and disclaimer

See the repository root `../README.md` (the **Disclaimer** section) for the standing terms. In short:
this is authorized public cryptanalysis; **no submitter code is redistributed**; everything builds
against the vendor reference you supply via `REF=` / `TV=`. Every number in this README is produced by
a script in this package — where a number is platform-specific (the cycle counts of part c), that is
stated at the number.

## The three parts

| dir | finding | needs vendor? | one-line |
|---|---|---|---|
| `dfr-exact/` | **F-0**, **F-1** | no (pure Python) | exact DFR for all nine sets, both decoders; C2's 2^-162 is unattainable; the submitted decoder is *better* than the specified one |
| `spec-literal/` | **F-1**, **F-2**, **F-3** | `REF=` + `TV=` | three `#ifdef` patches to the reference tree; the switch-less build reproduces 12/12 KATs, the spec-literal build reproduces 0/12 and (R1/D1 only) does not interoperate |
| `ternary3-timing/` | **CT-1** | `REF=` (avx2 tree) | the FO re-encryption's `ternary3` rejection loop leaks the decrypted `m'` through decapsulation time; present under SHA3, readable on rejected ciphertexts |

## Environment

All work was done on an **Intel Xeon Gold 6230R** (Cascade Lake, 2.10 GHz), **104 cores / 251 GB**,
Ubuntu 22.04, `/usr/bin/gcc` **11.4.0** (the submission's own compiler and `CFLAGS`), `clang` 17 for
the aarch64 cross-checks (not needed to reproduce anything below). **All timing is core-pinned with
`taskset -c 100`**, classes strictly interleaved and never batched. Python is CPython 3 + NumPy for
`dfr-exact/`.

## How to build against the submission

Obtain the NEV submission package (not included). The three parts point at different trees:

```
NEV/Implementations/Reference_Implementation/NEV-C1        <- spec-literal REF (any set dir works)
NEV/Implementations/Optimized_Implementation/avx2/NEV-R1   <- ternary3-timing REF (the avx2 tree)
NEV/Test_Vectors                                           <- spec-literal TV (KATs, read-only)
```

All twelve set directories inside a tree are byte-identical apart from the Makefile's default target;
the parameter set is chosen only by `-DPARAMS=1..12`, so any one set dir works as `REF`. **Nothing
under `REF`/`TV` is modified** — each part copies the tree into its own `work/` and applies our
patches to the copy. Run everything, or one part:

```
# (a) exact DFR, no vendor code:
./dfr-exact/run.sh

# (b) spec-literal conformance:
REF=<...>/Reference_Implementation/NEV-C1 TV=<...>/NEV/Test_Vectors ./spec-literal/run_all.sh

# (c) ternary3 timing channel:
REF=<...>/Optimized_Implementation/avx2/NEV-R1 \
  [REF_REF=<...>/Reference_Implementation/NEV-R1] ./ternary3-timing/run_all.sh

# or the top-level driver (runs the parts whose variables are set):
REF=<ref set> TV=<Test_Vectors> REF_AVX2=<avx2 set> ./run_all.sh all
```

---

## (a) `dfr-exact/` — F-0 and F-1, exactly, with no vendor code

Pure Python/NumPy (`nev_dfr_decoders.py`, `verify.py`, `sim_c2.py`, `summary.py`, `probe_v.py`,
`results.json`). No approximation is made: every distribution is integer-supported and bounded, every
convolution is exact and complete, the summation region is the exact event region, so there is **no
error term**. Peak RSS 55 MiB for the main computation (2.34 GiB for the Monte-Carlo cross-check),
one core, all nine sets in ~9 s.

```
./dfr-exact/run.sh          # models A/B, summary, verify (V1-V4), Monte-Carlo -- a few minutes
```

**F-0 — NEV-C2's published DFR is unattainable (Medium; does NOT breach the threshold).**
The exact recomputation gives, for C2, an upper bound `DFR <= 2^-141.53` and a **rigorous lower bound**
`2^-152.72`. Table 2 claims `2^-162` and Table 7 claims `p* = 2^-173`; both sit **below** the lower
bound, so they are not attainable — the authors' number is **20.3 bits** optimistic. The cause is
localised: out of six single-parameter substitutions, **only** interchanging `chi_f` and `chi_g` for
C2 reproduces both published values (to the 1.07/1.15-bit rounding offset the authors show on every
other set), and a `5.12e7`-sample Monte-Carlo in `Z[x]/(x^1024+1)` confirms the tabulated pairing and
rules out the swapped one at ~50 sigma (`sim_c2.py`: simulated mean/var/kurt -1.9894 / 2735.67 /
3.0042 match the exact model to 3 figures; the swapped model is 12.7 % low).
- **The error is absorbed, and we say so.** `2^-141.5 << 2^-128`, so C2 clears its own DFR target.
  Charging the full 20.3 bits against Table 7's C2 failure-boosting row (target `(256,128)`, published
  headroom `(68,74)`) still leaves **48 bits classical / 54 bits quantum**. The one thing we cannot
  close is the *recomputed* Table 7 row itself: the script behind Table 7 does not ship and its costs
  are not monotone in `p*` alone, so we cannot re-derive `(324,202)` from `2^-152.72` — we can only
  bound the headroom. This is stated as unresolved, not as a breach.
- Validation: our model reproduces the authors' own `p*_{j,y}` column to **0.02-1.28 bits** on the
  other eight sets (`summary.py`, Table 2), i.e. our model *is* spec §3.2. Self-check reproduces our
  six older stored per-block values to residual **<= 0.0043 bits**; `verify.py` V1-V4 all pass
  (brute-force cross-check, and float64 vs `longdouble` agree to **0.00 bits**).

**F-1 — the submitted decoder is BETTER than the specified one (Low; a favourable conformance defect).**
`pack.c poly_tomsg` centres on `(q-1)/2` and thresholds at `q` where spec §3.1 `Noise2Pt` says
`(q+1)/2` and `k(q-1)/4`. Algebraically this is the *same* union bound over the same 16 sign patterns
with a per-pattern threshold `q - Sum(y_i)` instead of the single `q-1`. Computed exactly for all nine
sets, the submitted decoder's DFR bound is **lower (better) by 0.07-0.44 bits** — effective threshold
shift **+1.003 to +1.009** units, favourable, every set. **This is a documentation issue in the safe
direction:** Table 2 describes the specified decoder; the shipped code is marginally safer than Table 2
says. 0 differing group decisions in 480 000 honest decryptions.

Reproduces (all from `./dfr-exact/run.sh`; the tables are in `logs/summary.log`):
- F-0 interval and the -20.28-bit C2 line: `python3 summary.py` (Table 2 row C2).
- F-0 cause + ~50 sigma: `python3 sim_c2.py`.
- F-1 column (c), all nine sets: `python3 summary.py` (Table 1/2 "delta(code-spec)").
- self-check + V1-V4: `python3 nev_dfr_decoders.py --model A --selfcheck` and `python3 verify.py`.

---

## (b) `spec-literal/` — F-1, F-2, F-3 as an executed KAT/interop differential (`REF=` + `TV=`)

The three deviations are expressed as three `#ifdef` patches to the reference tree
(`patches/spec-f{1,2,3}-*.patch`); `build_common.sh` copies `$REF` into `work/spec` and applies all
three, so the switch-less build is provably still the submission and the switches turn on each
deviation in isolation. Because the NTT, packers, hashes, DRBG and FO transform are shared, any
disagreement is attributable to the three patched sites and nothing else.

```
REF=<...>/Reference_Implementation/NEV-C1 TV=<...>/NEV/Test_Vectors ./spec-literal/run_all.sh
```

**Step 1 — our Algorithm 11 is correct (self-check first).** `cbd_eta_alg11()` at eta = 1,2,4
reproduces the submitted `cbd1/cbd2/cbd4` **coefficient-for-coefficient** — 0 differences in
27 648 000 coefficients (`SELFCHECK_ETA124=PASS`). Only then does the eta = 3,7 comparison mean
anything. (`run_selfcheck.sh` -> `logs/selfcheck.txt`.)

**F-2 — `cbd3`/`cbd7` are not Algorithm 11 (Low; interop on R1/D1 only).** At eta = 3,7 the submitted
composites differ from Algorithm 11 on **77.45 % / 85.07 %** of coefficients (max |Δ| 6/12). Not a
document ambiguity: Algorithm 11 is honoured for eta = 1,2,4 in the same file with the same helper and
`ceil(n*eta/4)` bytes and zero slack — an **internal inconsistency**, so no reading of the spec repairs
it (both Fig.-4 candidate readings are refuted outright by eta = 1,2,4; `FIG4_EXPLAINS_CODE=no`, and
the sorted-multiset differs in 2000/2000 buffers, so no permutation argument works either). Blast
radius is `chi_f`/`chi_g`/`chi_r` with eta in {3,7} = **R1, D1, D3** — **not `chi_e`** (`get_noisem_cbd*`
implement Pt2noise directly and never call `cbd3`/`cbd7`).

**F-3 — keypair nonce order is reversed (Low).** `ow_pke_keypair` samples `f` at nonce 0 and `g` at 1;
Algorithm 15 samples `g` at 0, `f'` at 1. Since `f` and `g` are not interchangeable (`pk = g/f`), a
spec-literal implementation derives a different key pair from the same sigma on **all 12 sets**.

**F-1 at KAT level.** `poly_tomsg` is reachable only from decapsulation, so F-1 cannot change a KAT
vector (it changes **0/24** configs); the experiment confirms the non-trivial half, that every honest
decapsulation still returns the encapsulator's shared secret with the spec decoder substituted.

Measured (from `logs/kat_diff.txt`, `logs/interop.txt`, `logs/isolate_encap.txt`):
- **base reproduces 12/12 submitted ICCS vectors byte-for-byte** (sanity; `cmp_kat.py` section A).
- KAT differential, 12 sets x 2 backends: **F-1 0/24 changed, F-2 6/24 (R1,D1,D3 x both backends),
  F-3 24/24, F-1+F-2+F-3 24/24** (`cmp_kat.py` section B).
- Interop, 200 key pairs x 12 sets x 2 backends x 2 directions = **9 600 cross decapsulations:
  8 000 succeed with an agreeing shared secret, 1 600 rejected — every cross encapsulation on
  R1 and D1** (rc = +1, no shared secret), both directions, both backends. 9 600 same-implementation
  control decapsulations: 0 anomalies. Ciphertext differs only on R1/D1 (`isolate_encap`: only the
  F-2 switch changes a ciphertext, and only for eta_r in {3,7}).

**The correct claim is not "NEV is not interoperable".** 10 of 12 sets interoperate perfectly and
8 000 of 9 600 cross decapsulations agree. The unconditional claim is the KAT one (F-3, all 12); the
interop failure is F-2 and is confined to **R1 and D1**.

---

## (c) `ternary3-timing/` — CT-1: a plaintext-dependent timing channel that survives SHA3 (`REF=` avx2 tree)

The FO re-encryption inside decapsulation calls `poly_sample_r` -> `poly_bias3_ternary` ->
`ternary3`, whose accept loop `while (ctr < 16 && i < buf_len) { if (buf[i] < 243) {...} i++; }` runs
once per *examined* byte. The number of rejected (`>= 243`) bytes is a deterministic function of the
re-encryption randomness, which is a deterministic function of the decrypted plaintext `m'`. So
decapsulation time is (essentially) linear in a function of `m'`. The instrumentation is expressed as
patches (`patches/instr-*.patch`) that only add counter globals; `time_*` binaries link the **pristine**
tree, the instrumented tree is used only to classify ciphertexts.

```
REF=<...>/Optimized_Implementation/avx2/NEV-R1 \
  [REF_REF=<...>/Reference_Implementation/NEV-R1] ./ternary3-timing/run_all.sh 6 12
```

**CT-1 = Medium** ("measured, repeatable channel, no recovery"). The points below are as measured on
the reference rig (Xeon Gold 6230R, `taskset -c 100`); the logs shipped in `logs/` are a fresh re-run
from a clean checkout on the same rig. **Absolute cycle counts are hardware- and load-dependent**;
what is invariant is the *shape* — a monotone, roughly linear response, sign-correct class separation,
and a signal many times the same-class control.

- **Present under `-DUSE_SHA3` (the spec default), so it is NOT killed by ngcc's `pseudohash`/
  `pseudoXOF` rule.** `report-classification.html` states verbatim: *"For contest `pseudohash` and
  `pseudoXOF`, assume ideal replacement primitives with the same external dimensions and parameters. A
  finding that disappears solely on that replacement is not publishable."* Under SHA3 the `ternary3`
  *refill* fires **0/20 000** — yet the rejection-scan slope and the class separation are unchanged.
  That is the line between CT-1 and the withdrawn refill channel (C6/N-2), which *does* vanish under
  SHA3. The rejection statistic is **identical under both backends** (mean rejections/decap ~= 21.97,
  sd ~= 4.8, refills 0 under SHA3 vs ~8e-4 under the SM3 XOF): it is a property of `ternary3`'s 13/256
  rejection rate, not of the XOF block size.
- **Slope: 18.92 (P6/SHA3), 32.63 (P12/SHA3) cycles per rejected byte**, strictly **monotone over 22
  buckets with 0 inversions** (reference-rig figures; `logs/slope_p6_USE_SHA3.txt`,
  `slope_p12_USE_SHA3.txt`).
- **The leak is 100 % attributable to `ternary3`.** The isolated `poly_sample_r`, bucketed by exact
  rejection count, has slope **17.56** — matching the whole-decap slope (`logs/sampler_slope_p6.txt`).
- **Class separation +434 / +504 / +708 / +402 cycles** (P6-SHA3 / P6-ICCS / P12-SHA3 / P12-ICCS),
  **sign-correct 15/15 batches**, against same-class **negative controls of +0…+28 cycles — the signal
  is 12-36x the control**. The control is published alongside every signal (`time_*_aa.txt`,
  `time_*_bb.txt`), and is what makes the effect credible.
- **Usable on rejected, attacker-chosen ciphertexts.** A one-byte ciphertext flip is rejected
  **20 000/20 000** by `verify`, but `poly_sample_r` runs *before* `verify`, so the signal survives
  with slope **19.00 / 32.15** (`logs/time_tam_*`, `logs/slope`… on the tampered set). A static-key
  decapsulation service leaks ~4 bits about the plaintext per rejected query.
- **Affects PARAMS 6 = R3 (a recommended set) and 10/11/12.** R1/R2/C1/C3 show **no measurable message
  dependence** (fixed-vs-fixed: 0/16 pairs over threshold, indistinguishable from their own null;
  `logs/fvf_p4.txt`, `fvf_p5.txt`). **No key dependence** on any set: the distinct-key spread is at the
  noise floor (relative ~1e-3) and, on a quiet core, below the byte-identical-`dup` control
  (`logs/keys_*`).
- **Machine-code hygiene, checked clean:** `0` `div`/`idiv` in 80 objects across both trees x 4 sets x
  2 backends (`logs/divscan.txt`); `ntt`/`invntt` compile to 0 conditional jumps; `verify` has no
  data-dependent early exit; the CT-5 `mont2_inverse` early exit fires **0/20 000** keygens (keygen-only,
  discarded candidates only; `logs/keygen_retry_*`).

**Boundary (stated, not hidden).** Medium means *there is a measured, repeatable channel but no
recovery*. We did **not** build the chosen-ciphertext sweep that would turn a plaintext-checking oracle
into `f`, and NEV's grouped-vector decoder is not an off-the-shelf PC-oracle target, so we do **not**
argue High. The fix is to make `ternary3` consume a **fixed** number of bytes (branchless `<243` mask
+ constant-time compaction); enlarging the refill margin (the N-2 recommendation) does **not** fix
CT-1, because the refill was never the leak under SHA3.

---

## What we do NOT claim

- **No key recovery, no IND-CCA break, no forgery.** `break_score` stays 1.
- **Nothing here puts a parameter set below its claimed security level.** In particular F-0 does
  **not** breach a threshold: corrected C2 is `2^-141.5 << 2^-128`, and charging the full 20.3 bits
  against Table 7's C2 cost still clears `(256,128)` with 48/54 bits to spare.
  Scope note, so this is not read as more than it is: this package covers the decryption-failure
  analysis, spec/code conformance, and a timing channel. It makes **no independent claim about the
  lattice hardness estimates** in Table 2 columns 8-10 — those we reproduced separately, with one
  gap we are still closing (the `dual_hybrid` estimate for NEV-R3 overflowed our estimator run and
  is not yet resolved), so we neither confirm nor contest that column here.
- **F-1 is favourable**, not a risk: the submitted decoder's DFR bound is *lower* than the specified
  decoder's on all nine sets.
- **Interoperability fails on R1 and D1 only** (2 of 12 sets). NEV is **not** "non-interoperable" in
  general; the unconditional defect is the KAT one (F-3), and 10 sets interoperate perfectly.
- **F-2 does not touch `chi_e`.** Blast radius is `chi_f`/`chi_g`/`chi_r` with eta in {3,7} = R1, D1, D3.
- **CT-1 is Medium, not High**: a measured channel, no recovery path executed.
- **CT-5 / the NEON `_pext` path are refuted** and are not part of this package (the `_pext`
  cross-check involved a verbatim vendor snippet and, being a refuted non-finding for CT-1, is
  intentionally omitted).

## Errors we corrected ourselves (kept, per the integrity habit)

- **F-1 direction.** Our first pass estimated the decoder deviation with a Gaussian tail as
  *"≲1.7 bits, unfavourable"*. The exact per-pattern union bound shows it is **0.07-0.44 bits and
  favourable**. The mistake was pushing a worst-case *realisation* of a discrete correction
  (`Δ=4`, the extreme of a Binomial(4,½)) through a derivative of a log-probability; the correct
  average is the deterministic `+1` threshold shift. The Gaussian *slope* was actually accurate to ~1 %;
  the error was in Δ.
- **The C2 gap.** Our first pass read the ~27-bit C2 discrepancy as **our own** conservatism. Decomposed
  exactly: our worst-case-`e'` conservatism is worth only **6.4 bits**, the uncompressed→rounded step
  goes the **wrong** way (-0.23 bits), so **20.5 bits are in the authors' number** — it is theirs, not
  ours, and the claim lies below a rigorous lower bound. Guessing "probably ours" was the FlexTree
  mistake in miniature (re-using our own model as the explanation instead of testing it).
- **F-3 count.** First stated as "6 of 12, because chi_f != chi_g". It is **all 12** (`f`/`g` are not
  interchangeable regardless of distribution), and the chi_f != chi_g sets are **5**, not 6.
- **F-2 blast radius.** First stated to include `chi_e`; corrected to exclude it (`get_noisem_cbd*` do
  not call `cbd3`/`cbd7`).

## Cleanliness

No submitter source is redistributed. Our changes to vendor code are expressed **only** as unified
diffs under each part's `patches/` (three spec `#ifdef` patches; three instrumentation patches that add
counter globals). Each patch was verified to reproduce its target file byte-for-byte when applied to
the pristine vendor source. `work/`, `bin/`, `obj/`, `data/`, `xfer/`, `kat/` are build artifacts and
are git-ignored; the submission's KAT vectors are read from `TV=` and never copied in. A clean-check
was run over the committed tree for author identifiers, private contact strings, machine-absolute
paths, and vendor function bodies outside patch context; it comes back clean. Absolute paths in run
logs were rewritten to relative form. (The reproduction package is prepared under a private working
tree; none of its identifiers appear here.)

This analysis was prepared with AI assistance (Anthropic Claude). Every number above is produced by a
script in this package; platform-specific cycle counts are labelled as such.
