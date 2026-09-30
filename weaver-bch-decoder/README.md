# weaver-bch-decoder — Weaver: Berlekamp–Massey bug in the BCH decoders, and the real DFR of the submitted Weaver-1024

**Scope: implementation-level (severity B).** This package backs our Round-1 public comment on Weaver. It
contains **no key recovery**, and nothing here is a design-level break. It is kept in this repository,
like `yuanyang-dsa-sampler-constant`, because the comment cites a reproduction package.

## What we claim (and verified)

1. **The BM step mis-decodes some error patterns of weight ≤ t.** In `compute_error_locator_polynomial`
   (`bch_high.c:209`, `bch_low.c:212`; identical in all 12 BCH files, reference and optimized, submission
   and GitHub `Akutamatsu/weaverkem` at `ca99d0f`), the next discrepancy is summed over
   `for (j = 1; j <= i+1; j++)`. The sum must run to deg(elp), which can exceed i+1 in binary BM. The
   decoder then returns a wrong word and does **not** return -1. t = 2 (Weaver-640) never reaches that state.

   Direct decoder test, data-bit errors, 20000 trials per weight (`logs/run_*/bch_direct.txt`):

   | code | e | correct, original | correct, fixed |
   |---|---|---|---|
   | W-1024 high BCH(255,223,4), 220+32 | 4 | 19923/20000 | 20000/20000 |
   | W-1024 low BCH(63,39,4), 36+24 | 4 | 19720/20000 | 20000/20000 |
   | W-2048 high BCH(511,448,7) | 4 / 5 / 6 / 7 | 19959 / 19921 / 19897 / 19832 | 20000 each |
   | W-2048 low BCH(127,78,7), 64+49 | 4 / 5 / 6 / 7 | 19863 / 19691 / 19567 / 19398 | 20000 each |

   Codec level, on the actual decapsulation decoding path of GitHub `ca99d0f` (the commit that adds the
   missing W-1024 high-layer decode): `poly_frommsg` → add (q+1)/2 to e high-layer payload coefficients →
   `poly_tomsg` (`logs/run_ca99d0f/codec_search.txt`). W-1024 e = 4: 83/20000 wrong messages. W-2048
   e = 4..7: 0.20 / 0.35 / 0.51 / 0.84 %. After the fix: 0 for every e ≤ t. With e = t+1, both versions fail
   in 100% of trials.

   Minimal example (`logs/run_ca99d0f/codec_replay.txt`): W-1024, all-zero message, flip coefficients
   32, 61, 143, 209. The original returns `0001000080000004000000000020000200010000000000000200400000000000`:
   none of the 4 errors is corrected, and bits 15, 106, 126, 198 are also flipped. The fixed decoder returns
   all zeros.

   **Fix** (`patches/bm-discrepancy-loop.patch`): `for (j = 1; j <= t && j <= 2*i+2; j++)`. The existing
   mask keeps the loop constant-time. With the fix, the regenerated KATs are byte-identical to those of the
   unmodified code, both for the submission (matching the shipped `Test_Vectors`) and for `ca99d0f`
   (`logs/run_*/kat_sha256.txt`).

2. **The submitted Weaver-1024 does not decode the high layer at all** (already reported on the forum and
   in ngcc.dev kem-39-2; re-checked here). One injected high-layer error through `indcpa_enc`/`indcpa_dec`:
   W-640 decrypts 200/200 correctly, W-1024 0/200, W-2048 200/200 (`logs/run_submitted/flip1.txt`). At
   `ca99d0f`, all three sets decrypt 200/200 correctly (`logs/run_ca99d0f/flip1.txt`).

3. **Real DFR of the submitted Weaver-1024: about 2^-45.5 to 2^-47.5, against the claimed 2^-231.7**
   (`dfr/`, `logs/dfr/`). The value is the probability that any of the 220 uncorrected high-layer payload
   bits is wrong. We compute it two ways:
   - 2^-47.5 from an exact model. `dfr/model.py` enumerates every noise term from the code's own
     Compress/Decompress formulas and Invq tables and convolves them exactly.
   - 2^-45.5 using the spec's own per-bit rate, 2^-53.3, backed out from Table 3.

   The model is validated against 3–3.8·10^8 measured coefficients per set (`dfr/harness.c`,
   `logs/dfr/w*.txt`, `logs/dfr/analyze.json`). σ matches to 0.02%, and tail probabilities agree within 1%
   down to 4.6σ.

## What we do NOT claim

- **The DFR values are extrapolations, not observations.** Everything below about 2^-30 comes from the
  validated model. No raw bit error of either layer occurred in any measured run.
- **The effect of the BM bug on the honest DFR is an extrapolation.** Weaver-1024's lower layer moves from
  about 2^-231.7 to about 2^-190. In honest use the DFR stays negligible.
- **Failure boosting is a cost table, not an attack.** For the submitted Weaver-1024,
  `dfr/boost.py` → `logs/dfr/boost_W1024.log`:
  - An attacker who pre-selects large-‖r‖ ciphertexts expects the first decryption failure after about
    2^41–2^47 decapsulation queries, with 2^48–2^61 offline encryptions.
  - We did not compute, and do not claim, the cost of turning failures into key recovery.
- **Error dependency (spec-accuracy remark only).** Conditioning on ‖s‖ and ‖r‖ moves the DFR by 7–19 bits
  relative to the independence model. With the decoders fixed, Weaver-1024 is 5–9 bits worse than Table 3;
  Weaver-640 is about as claimed; Weaver-2048 is better than claimed. Everything stays far below 2^-128.
  The conditional model carries about ±1 bit of calibration error per bit error rate
  (`logs/dfr/model_*.log`).

## How to run

```
REF=/path/to/Weaver/Implementations/Reference_Implementation ./run_all.sh          # ~30 s, steps 1-5
REF=/path/to/Weaver/Implementations/Reference_Implementation ./run_all.sh --dfr    # + model (~15-20 min/set, 1 thread)
```

- `REF` must contain `WeaverKEM-128/256/512`. Both the submission package and the GitHub repository at
  `ca99d0f` (`Implementations/Reference_Implementation`) work.
- `$REF` is never modified. Sets are copied to `./work/` and the one-line fix is applied there.
- `logs/run_submitted/` and `logs/run_ca99d0f/` are the real outputs of the default run against each tree.
- The full noise measurement uses the instrumented tree (`patches/dfr-instrument-mp.patch`, which stores
  `mp` before `poly_tomsg`). Run `work/instr-<set>/harness <nkeys> <nct_per_key> <seed> <out>`; the
  logged runs used 3000/1500/600 keys × 1000 ciphertexts.

No vendor code or binaries are included. All harnesses use only the vendor's public API plus the one
recorded instrumentation. The DFR harness reads the secret only to measure noise, since measuring noise
requires it; it plays no part in any attack claim.

This analysis was prepared with AI assistance (Anthropic Claude). Every number above comes from running
the code in this package against the vendor trees named above.
