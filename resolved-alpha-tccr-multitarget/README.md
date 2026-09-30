# ReSolveD-alpha: no per-node tweak in the BAVC/TCCR tree -> within-signature multi-target key recovery at ~2^{lambda-8}

A **design-level** finding on **ReSolveD-alpha** (ICCS NGCC round-1 code-based signature, `sign-21`,
RSD + VOLE-in-the-Head). The GGM tree in `BAVC.Commit` is expanded with
`TCCR(x, s, iv) = Enc_{x'_R || iv}(i || x'_L) xor (i || x'_L)`, `x' = x xor s`, whose only tweak is the
per-signature `iv` (the first plaintext byte `i` is the output-block index, not a node index;
`tccr.c:13-51`). Inside one signature every node is expanded under the same `(s, iv)`, so the
`T = |id-list|` revealed nodes of `decom_I` are `T` simultaneous targets for one enumeration over the
hidden parents: `TCCR(p)`, `TCCR(p) xor p` (upper half) or `TCCR(p xor const_b)` (lower half,
`bavc.c:53-63`). Expected cost of recovering the **full witness (= signing key) from one signature**:

| set | median T | key recovery (TCCR evals) | claimed |
|---|---|---|---|
| 160s/f | 128 / 134 | ~2^153 | 128 (unaffected) |
| 256s/f | 221 / 217 | **~2^248.2** | 256 |
| 384s/f | 330 / 328 | **~2^375.6** | 384 |
| 512s/f | 437 / 439 | **~2^503.2** | 512 |

In the spec's own unit (Sec. 5.2, "at least 2^lambda symmetric operations") each candidate costs one key
schedule + one block-cipher call (block 0 filters), the same per-candidate cost as brute-forcing any
lambda-bit key, so the shortfall is at least `log2(T+1) - 1 ~ 6.8 / 7.4 / 7.8` bits. **Not a practical
break** (7-9 bits), but a concrete bound below the claimed level for the 256/384/512 sets, and it
contradicts spec Sec. 7.1.2-7.1.3, which copy FAEST v2 Sec. 9.1.2 while dropping the per-invocation
tweak that FAEST's "no multi-target attack" sentence depends on. The spec's own Theorem 8.12 carries the
`4 q_E mu / 2^rho` multi-target term (`mu` = construction queries under one tweak); the parameters
simply do not budget for it. Precedent: eprint 2024/252 broke the original ReSolveD's unsalted tree
*across* signatures; the alpha version's `iv` fixes that and leaves this *within*-signature residue.

Every number here is produced on this machine from the **unmodified** vendor reference (Keccak backend =
ideal-primitive setting); the reference is never bundled.

## What is completed vs extrapolated

- **Completed (real parameters, 256s/256f/384s/512f):** (a) every one of the `T` revealed nodes equals
  the stated public function of its hidden parent (0 failures); given one hidden parent, **public data
  only** yields the hidden leaf (matches the published leaf commitment), the full witness (equals the
  signer's), and a fresh-message signature accepted by the unmodified `sig_verify`; a one-bit witness
  flip is rejected.
- **Completed (256s/256f/384s/512f, no oracle):** (b) the attacker is given all but `B` bits of one
  hidden bottom parent (the feasible slice of the `2^lambda` search) and brute-forces the rest with the
  submitted `tccr_hash`, testing each guess by hash-set membership against **all `T` real revealed node
  values of a real signature**; the search itself discovers which target it hit, and from that hit the
  same public-data chain recovers the witness and forges. `B = 20` on all four sets and `B = 22` on
  256s (`FULL=1`: `24`) all pass.
- **Completed (256-bit TCCR):** (c) the `/T` factor is a real total-work speedup: `T = 216` targets in a
  `2^B` window, `B = 20 / 24` (`FULL=1`: `28`), randomized search needs `2^B/(T+1)` evaluations with
  ~0.3 hash probes per candidate, independent of `T`; a linear scan (what a naive implementation of the
  test would do) costs `216x` more comparisons. Memory is `T` words.
- **Extrapolated (not run):** the full-size `2^{248+}` search itself.

## Threat model and purity

EUF-CMA, **one honest signature**, public key only. `h2_witness.c` regenerates the signer's tree solely
to (i) check relation (a) against ground truth and (ii) hand one hidden parent to the recovery chain
in place of the infeasible full search (marked `ORACLE` in-source). `exp_genuine.c` uses the signer's
tree only to fix the `lambda - B` "known" bits of the search window; the search, the membership test,
the recovery and the forgery read only the signature and the public key.

## Run

```
REFROOT=/path/to/ReSolveD-alpha/Implementations/Reference_Implementation ./run_all.sh     # ~5 min
FULL=1 REFROOT=... ./run_all.sh                                                           # + B=24 / B=28, ~30 min
```

`REFROOT` must hold the unmodified vendor instance dirs `ReSolveD-alpha-{256s,256f,384s,512f}`. The
script copies each into `work/`, compiles our `src/*.c` inside the copy (they `#include` the vendor
sources) and runs. `src/tcount.py` reads the vendor `parameters.h` files. `results/run_all.log` is a
complete run on this machine.

## Spec errata (implementations are fine) noted in the same review

- Sign pseudocode lines 22-30: `ctr` is not incremented when `BAVC.Open` returns bot (literal
  implementation loops; both shipped implementations increment).
- Lemma 3.5 Eq. (5): shift uses the group index instead of the block-in-group index, so identical
  violating blocks cancel in characteristic 2; `QS.RSDProve` line 13 same slip. Implementations do not pack.
- `BAVC.Verify` omits the zero-padding check the code performs; `l_vole` table and CoinHash input list
  differ from the code.

## Suggested fix

Tweak `TCCR` (and the leaf `PRG`, which uses the fixed tweak `0^8` for every leaf) by node index /
instance, as FAEST v2 does, or raise `lambda` by `ceil(log2 T_open) + 1` bits; delete the
"no better than single target" statement in Sec. 7.1.2/7.1.3.

This analysis was prepared with AI assistance; every number comes from running the submitted code or
from the spec's own tables.
