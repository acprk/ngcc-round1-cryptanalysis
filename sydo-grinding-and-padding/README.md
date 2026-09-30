# SYDO (NGCC sign-28) — grinding soundness and BAVC opening padding

Verification package for two findings in the NGCC round-1 submission **SYDO**.

**F1 (design + implementation).** The grinding parameters are self-contradictory: Sec 5.2 requires
`tau*log2(N) - log2(d) + wgrind >= lambda` and Table 5.3 takes equality, so
`tau*log2(N) + wgrind = lambda + 2`; but `chall3` is only `lambda` bits and Algorithm 3 splits it into
`wgrind` zero-checked bits plus `lambda - wgrind` bits fed to `DecodeAllChall`, which needs
`tau*log2(N) = lambda - wgrind + 2`. Two bits short, every set. Both implementations resolve this by setting
`delta_bits = lambda - wgrind + ceil(log2 d)` and enforcing only `wgrind - 2` zero bits, so the realised
soundness is `lambda - 2` (158 / 254 / 510) for all six sets, and **13 of the 60 shipped KAT signatures
satisfy the spec's own grinding condition** — a verifier written strictly from Algorithm 3 rejects 47 of them.

**F2 (implementation, Reference only).** Algorithm 13 lines 21–22 require the BAVC opening padding to be all
zeros. The Optimized tree checks it (`vector_com.inc`); the Reference tree does not
(`bavc_impl.inc` falls through to `ok = true` at L446). Result: signature malleability against a property the
spec does not claim (no SUF), **and the two trees return opposite verdicts on the same byte string**.

A third observation — SYDO-512's `seed_sk` being exactly one SM3 block, so the witness is a function of a
256-bit chaining value — is **deliberately not reported as a finding**: it disappears under the ideal
replacement of the contest `pseudoXOF` mandated by the report classification, and SYDO's Sec 4.2.2 / Sec 5.1.2
/ Appendix A designate the contest placeholder, disclaim it, and already give an AES+SHAKE instantiation. The
check is kept in the record only so readers know it was done.

## Layout

```
src/layout.c        prints delta_bits + enforced zero bits by calling the vendor library's own
                    sydo_ref_delta_bits() / sydo_ref_unused_delta_bits()   [Reference only]
src/xv.c            gen / pad / ver : sign, locate+overwrite the free bavc_open tail, cross-verify
src/sweep.c         exhaustive single-bit flip sweep over a byte range; prints every accepting flip
tools/kat_grind.py  shipped KAT signatures vs the SPEC grinding condition (Alg.3 line 7)
tools/kat_ctr.py    shipped grinding counters vs spec Table 5.5, and vs Table 5.5 / 2^(wgrind-enforced)
tools/qs_cheat.py   scaled GF(2^8) model of one degree-4 QuickSilver constraint: the d-root cheating
                    strategy and its d/|Delta| soundness error  (a MODEL, not an attack on SYDO)
tools/thm25_bound.py  what SYDO's own Theorem 25 yields once the Katz-Wang loss 1/(1-rho_RSD) is
                    included: 157.0 / 254.3 / 509.9, from the spec's Tables 5.2/5.3 alone (no build)
results/            our logs: layouts.txt, kat_grind.log, kat_ctr.log, qs_cheat.log,
                    padding_crossverify.log, SWEEP-SUMMARY.md
```

## Running

The submitter's code is **not** included. Point `REF=` at the SYDO submission tree — the directory holding
`Implementations/` (or the two implementation trees at top level) and `Test_Vectors/`.

```sh
REF=/path/to/SYDO ./run_all.sh          # F1 only: Reference build + three analysis scripts
REF=/path/to/SYDO ./run_all.sh full     # F1 + F2 cross-verification + a bounded sweep
```

Useful overrides: `SETS="160f 256f"` to restrict parameter sets, `WORK=/tmp/sydo` to move the scratch tree,
`CC_REF` / `CC_OPT` / `CXX_OPT` to pick compilers.

### Toolchain

- Reference: `gcc >= 9`, `-std=c11`. Builds out of the box.
- Optimized: needs `clang >= 17`. Its Makefile hardcodes `-std=c23` / `-std=c++23` and gates the build on a
  self-test for those exact spellings; clang-17 implements the same language as `-std=c2x` / `-std=c++2b` and
  rejects `c23`, while gcc-12 fails separately on `static_assert(false)` inside a template (C++ P2593).
  `run_all.sh` detects this and rewrites the spelling **in its own scratch copy only**. This is a build
  portability issue, not part of either finding.
- The Optimized objects are LTO bitcode, so the harness is linked with `clang++ -flto`.

## What each step proves

`layout.c` is the load-bearing measurement for F1: the enforced-zero-bit counts come from the vendor
library's own accessors, not from our reading of the source. `kat_grind.py` and `kat_ctr.py` need no build at
all — they parse the published test vectors — so F1(c) is independently checkable by anyone with the
submission package and Python. `qs_cheat.py` is a scaled model; it justifies the `-log2(d)` term in SYDO's
own inequality, and the `lambda - 2` figure follows from combining it with the bit count `layout.c` reports.

`xv.c` establishes F2 positively (Reference accepts a mutated padding that the Optimized tree rejects) and
`sweep.c` establishes it negatively: it is what licenses the claim that the padding is the *only* single-bit
malleable surface, rather than merely one of them. Neither reads a secret key; both use only `pk`, `msg` and
the signature.

## Measured cost (104-core / 251 GB)

F1: under five minutes for all six sets (one Reference build per set, then seconds of Python).

F2: dominated by verification. Mean cost of one `sig_verify`, from the sweep logs:

| set | Optimized | Reference |
|---|---|---|
| 160f | 7.47 ms | 98.72 ms |
| 160s | 28.67 ms | 268.66 ms |
| 256f | 15.72 ms | |
| 256s | 61.25 ms | |
| 512f | 72.02 ms | |
| 512s | 323.57 ms | |

The 18 cross-verification trials are minutes for 160/256 and longer for 512 (`pad` does one verification per
probed byte).

**The default bounded sweep is enough.** Sweeping only the last 724 bytes of the 160f signature (5,792 flips)
gives `ref 1,120 accepted / opt 0 accepted` — the *same* 1,120 as the exhaustive 53,792-flip sweep, because
the whole padding run `[6540,6680)` lies inside that window. Measured: 24.5 s (Optimized), 8.7 min
(Reference).

The exhaustive sweeps in `results/SWEEP-SUMMARY.md` (13 signatures complete at 1,602,528 flips / 0 accepted,
three 512-level runs still going) cost roughly 68 CPU-hours, about an hour of wall clock per set at 24-way
parallelism, worst at 512s (~86 min of CPU per 2000-byte chunk). They are **not** needed to confirm either
finding; `run_all.sh` runs only the bounded version by default.

## Provenance

Every number here comes from building and running the submitted code, from parsing the shipped test vectors,
or from `tools/qs_cheat.py`, which is labelled as a model wherever it is used. Prepared with AI assistance as
part of an authorized public evaluation.
