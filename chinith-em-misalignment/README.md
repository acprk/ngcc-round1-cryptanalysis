# Chinith / uBlockith-EM: a one-block misalignment in the OWF constraint chain

Chinith is an ICCS NGCC round-1 VOLE-in-the-head signature (FAEST-like) with three
one-way-function backends (SM4th, uBlockith, Vistrutith). This package documents and
reproduces a defect in the **uBlockith-EM** constraint system that is present in both the
June 30, 2026 specification and the submitted code, and that is **not** covered by the
authors' announced corrections (issues 1-4, September 30) nor by the `ctr` retry issue
already discussed on the PKC forum.

Everything here was measured on the official round-1 archive
(`Chinith.zip`, SHA-256 `4d31ba3fe8718f59901b7efdf01b4179912ef8e04f58b4b6dbba84186f002283`).
No vendor code is redistributed; point `REF=` at the vendor
`Implementations/Reference_Implementation/` directory.

## The defect in one paragraph

uBlockith-EM proves `y = E_x(k) xor k` with the full 24-round uBlock-256. The extended
witness is `S0 = k, S2, S4, ..., S22` (12 blocks, `l_enc = 3072`), and `EncCstrnts`
(spec p.68) checks 12 double-round transitions, the last of which should land on
`out = k xor y`. In the EM branch of `OWFConstraints` (p.69), step 9 takes `in = w[0..255]`
and step 17 selects `w~ = w[l_ke ..]` with `l_ke = 0`, so `w~` still begins with `S0 = in`.
`EncCstrnts` step 6 then prepends `in` once more:

```
w* = in || w~ || out = in || in || S2 || S4 || ... || S22 || out      (14 blocks)
```

Every transition is shifted by one block: iteration `j = 0` demands
`DoubleRound_0(in) = in`, which an honest witness never satisfies; iterations `j = 1..11`
only relate prover-chosen blocks to one another; and the last iteration reads block 12
(`= S22`) instead of `out`, so **`pk2` never enters the specified relation**. The reference
code has the same prepend (`ublockith_ublock_256.c:181,190,264`; `ublock_constraints.c:778-784`,
`ENC_W_STATES = 11`, `S22` dropped), but it reads `out` directly in its
`i == UBLOCK_ROUNDS - 2` branch, so `pk2` *is* bound in the code. See `docs/spec-excerpt.txt`.

## Consequences (what is demonstrated)

| # | statement | scope | evidence |
|---|---|---|---|
| A | With the announced issue-1 fix applied (hash `a_tilde_0` into `chall_3`), **every honest uBlockith-EM signature is rejected** (0/5, both sets, reference and optimized); shifting the encryption witness by one block restores 5/5. The non-EM sets verify 5/5 (harness control). | spec + code | `harness/run_all.sh` |
| B | The spec-literal verifier accepts, for **any message and any `pk2`**, any `in` with `DoubleRound_0(in) = in` under the public round keys derived from `pk1`, plus the freely computed chain. Shown in the clear: constraints `j = 1..11` pass, only `j = 0` fails, by exactly `DR0(x) xor x`. | spec only | `fixedpoint/spec_witness.py` |
| C | Such a fixed point is findable in about **2^135.5** double-round evaluations by guess-and-determine (fix ~108 nibble-interleaved bits of `in`, SAT-solve the residual; wrong guesses refuted in ~17 s), versus the claimed 256-bit level. | spec only, certificational | `fixedpoint/logs/`, `docs/E-em-fixedpoint.md` |

Also in this package (same harness, different root cause): Vistrutith's QuickSilver
aggregation hashes the constant terms of three different constraint families as if they
were one polynomial's coefficients (`vistrutith_vistrutah_512.c:144`, `:166-170`); with
`a_tilde_0` bound, both Vistrutith sets reject all honest signatures (0/5) although all
1728 constraint values are zero in the clear. That is a completeness failure only.

## Honest limitations

* **C is an extrapolation.** The per-guess cost was measured (8 wrong guesses on a real key:
  mean 17.1 s, max 30.7 s; planted instances 22.4 s); the 2^108 enumeration was not run and
  cannot be. 2^135.5 is a certificational bound, not a practical attack.
* C applies to the **specification as written**, not to the shipped code (which binds
  `pk2`). For the code the defect is A only: a correctness failure that is masked today by
  the unbound `a_tilde_0` (sign-05-1) and surfaces as soon as that is fixed.
* C applies to the ~63% of keys whose `DoubleRound_0` has a fixed point (`pk1 = 0` has
  none: UNSAT in 207 s).
* Cost is counted in double-round evaluations (`T_ref = 9.3e-8 s` measured); a gate-level
  model would move the exponent by a few bits, not by 120.

## Fix

Either skip `S0` when selecting the encryption witness in the EM branch (spec p.69 step 17:
`w[N_block .. l_enc-1]`; code: `w + 32` at `ublockith_ublock_256.c:190/264`, tags/keys
`+256`), or do not prepend `in` at `EncCstrnts` step 6 for EM. Both restore the 24-round
chain ending at `out`. `harness/patch_em_offset_fix.py` is the one-line code version.

## Layout and how to run

```
harness/run_all.sh            REF=<vendor Reference_Implementation> ./run_all.sh
                              consequence A for uBlockith (control / EM / EM+fix) and Vistrutith,
                              plus the public uBlock-256/256 test vector on the vendor core
harness/patch_*.py            source patches applied to a COPY of the vendor tree
build.sh                      builds fixedpoint/dr0_lib (self-contained uBlock-256 double round;
                              REF= additionally cross-validates it against the vendor core, 0/10000)
fixedpoint/spec_witness.py    consequence B in the clear: `python3 spec_witness.py demo <pk1> <x> <pk2>` (random x -> only j=0 fails)
fixedpoint/dr0.py             bit-exact Python model + CNF encoder for DR0(x)=x
fixedpoint/e2_*.py            guess-and-determine sweep (structures a/b/c/d, cost curve, falsification)
fixedpoint/verify_g108.py     independent re-measurement at g=108 on a real key and a planted instance
fixedpoint/logs/              raw solver logs (vg108_real.log, vg108_planted.log, e2_*.log, ef_*.log)
docs/E-em-fixedpoint.md       full analysis (E1 whole-instance SAT, E2 guess-and-determine)
docs/spec-excerpt.txt         the relevant pseudocode lines of the submitted specification
docs/COMMENT-draft.txt        the public-comment text
docs/FINDINGS-zh.md           the wider Chinith finding list (Chinese), incl. de-duplication against known issues
```

Requirements: gcc, python3, `cryptominisat5` on PATH for the fixed-point scripts.
Keep `JOBS` (default 4) modest; the SAT scripts run at most a few solver processes.

## Relation to public discussion

* sign-05-1 (Feussner): `a_tilde_0` not hashed into `chall_3`, universal forgery of the
  shipped code. Our harness applies the authors' announced fix for it first; the
  misalignment is what remains.
* Authors' issues 2-4 (d=2/d=3 masks, EM/non-EM keyspace constraint, Deg2To3 lifting) and
  sign-05-3 (`ctr` not advanced) are independent of the block misalignment.
* The ICCS placeholder hash functions (`pseudohash`/`pseudoXOF`) are out of scope by the
  competition's own rule; nothing here depends on them.
