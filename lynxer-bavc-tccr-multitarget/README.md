# Lynxer: no per-node tweak in the BAVC/TCCR seed tree → within-signature multi-target key recovery

A **design-level** finding on **Lynxer** (ICCS NGCC round-1 VOLE-in-the-Head signature over the
Lynx OWF, `sign-14`). `BAVC.Commit` expands the GGM tree with `TCCR(x, s, iv)`, whose input is
`x' = x xor s`, key `x'_R || iv`, plaintext block `(i || x'_L)` with `i in {0,1}` the output-block
index — **not** a node index (`tccr.c:13-55`). Children are `TCCR(parent)` / `TCCR(parent) xor parent`
(upper half) and `(TCCR(parent), TCCR(parent with byte 0 flipped))` (lower half, `bavc.c:50-64`);
the leaf commitment uses the fixed tweak `0` for every leaf (`spec 5.4.7`). `s` and `iv` are computed
once per signature, so **inside one signature every node shares the same tweak**. The `T = T_open`
nodes revealed in `decom_I` are therefore `T` simultaneous targets for one enumeration over the hidden
parents; a hit yields the hidden leaf of a VOLE instance, hence `u_0`, hence the witness
`w = d xor u_0`. Because `w = k || v_1 || v_2` (`owf.c:793`), the first `lambda` bits of `w` **are the
OWF key `k`**, i.e. the full signing secret (`sk = owf_input || k`).

| set | T_open | key recovery (TCCR evals) | claimed |
|---|---|---|---|
| 160s/f | 129 / 139 | ~2^153 | 128 (unaffected) |
| 256s/f | 224 / 223 | **~2^248.2** | 256 |
| 384s/f | 332 / 336 | **~2^375.6** | 384 |
| 512s/f | 439 / 447 | **~2^503.2** | 512 |

Each candidate costs one key schedule + one block-cipher call (block 0 filters), the same per-candidate
cost as brute-forcing a `lambda`-bit key, so the shortfall is at least `log2(T_open+1) ~ 7.8 / 8.4 / 8.8`
bits for the 256/384/512 sets. **Not a practical break** (8–9 bits), but a concrete bound below the
claimed level, and it contradicts `spec 8.2.2`, which copies FAEST v2 while dropping the per-invocation
tweak that FAEST's "no multi-target attack" sentence depends on. Theorem 9.12 itself carries the
`4 q_E mu / 2^rho` term (`mu` = construction queries under one tweak = the whole tree). The 160 sets
target 128-bit classical security (`2^153 >> 2^128`) and are unaffected, as in `sign-14-1`.

Independent of `sign-14-1` (degenerate QuickSilver). It **survives the inverse-S-box revision**
(eprint 2026/1099, rev 2026-09-28, which changes only the S-box and explicitly keeps the FAEST BAVC
construction). ngcc.dev lists only `sign-14-1` for this candidate. Direct precedent: the sibling VOLEitH
candidate **ReSolveD-alpha**, reported for exactly this (ngcc.dev `sign-21-1`) with identical numbers.

Every number here is produced on this machine from the **unmodified** vendor reference (Keccak backend =
ideal-primitive setting); the reference is never bundled.

## What is completed vs extrapolated

- **Completed, 256s/256f/384s/512f** (`[a]`, `lx_struct`): every internal node's children equal the
  stated public `TCCR(parent)` recomputed under the single `(tccr_s, iv)` — `0` mismatches on
  49151 / 4863 / 69631 / 9215 internal nodes — so the tree is position-independent.
- **Completed, 256f, no oracle** (`[b]`, `lx_e2e`): from one honest signature and the public key, a
  scaled-down search (top `lambda-B` bits fixed, low `B` brute-forced with the submitted `prg_2_lambda`,
  tested against the **public** leaf commitment in `decom_I`) recovers instance 0's hidden leaf seed
  (matches the committed leaf), then `u_0`, `w = d xor u_0`, `k = w[0, lambda)`. The recovered `k` is
  **byte-for-byte the secret OWF key** and satisfies `owf(k, owf_input) = owf_output` from the public
  key; a secret key rebuilt from `k` signs a **fresh message** accepted by the unmodified `sig_verify`.
  `B = 20` ≈ 5 s; the default `B = 24` ≈ 226 s on one core.
- **Extrapolated (not run):** the full-size `2^{248+}` search itself. The `/T_open` factor is the
  standard multi-target hash-set argument; memory is `T_open` words.

## Threat model and purity

EUF-CMA, **one honest signature**, public key only. The vendor sources are patched only with read-only
`#ifdef LX_DEMO` hooks (`patches/lx-demo-hooks.patch`) that copy out internal values; **no transcript
byte changes** and KATs are unaffected. `lx_struct` uses the signer's tree solely to check relation
`[a]` against ground truth. In `lx_e2e` the other leaves of instance 0 are taken from the signer for
convenience — they are exactly what any verifier reconstructs from `decom_I` — while the **hidden** leaf,
the only secret-dependent value, is recovered by the search against public data; `u_0`, `w`, `k`, the
public-key check and the forgery then use only the signature and the public key.

## Run

```
REFROOT="/path/to/Lynxer/Implementations/Reference_Implementation" ./run_all.sh        # B=24 (~4 min)
REFROOT="/path/to/Lynxer/Implementations/Reference_Implementation" ./run_all.sh 20     # faster, ~15 s
```

`REFROOT` must contain the unmodified `Lynxer-{256s,256f,384s,512f}` instance dirs. `logs/run.txt` is
our run (`B=20`) against the archived NICCS package.

## Files

- `run_all.sh` — `[T]` T_open table, `[a]` structure (4 sets), `[b]` end-to-end key recovery + forgery (256f)
- `src/lx_struct.c` — position-independence scan, any parameter set
- `src/lx_e2e.c` — end-to-end key recovery + fresh-message forgery (256f)
- `patches/lx-demo-hooks.patch` — read-only debug hooks (applied to the `work/` copy only)
- `logs/run.txt` — our run

Prepared with AI assistance; every number comes from running the submitted code or the spec's own tables.
