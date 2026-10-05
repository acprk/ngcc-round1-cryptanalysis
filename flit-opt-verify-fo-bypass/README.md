# flit-opt-verify-fo-bypass — FLIT (kem-15): the optimized `verify()` accepts invalid ciphertexts

**Scope: implementation-level (severity B in this repository's A/B split; Critical class in the
ngcc.dev policy, same confidentiality-break kind as kem-02-6).** It affects every AVX2 tree —
`Optimized_Implementation/FLIT128`, `FLIT256`, `FLIT512` and
`Additional_Implementation/FLIT_FIPS202_OPT128`, `FLIT_FIPS202_OPT256`. The
`Reference_Implementation` and the FIPS202 reference trees are **not affected**. The defect is in the
original NICCS package (`FLIT.zip`) and is still present in the current GitHub tree
(`MathEternal/FLIT-NGCC`, HEAD `2d88b9f`); the commit that fixed the FIPS202 RNG did not touch it. This
package backs our Round-1 public comment on FLIT (kem-15). It is separate from the FLIT512 compression
mask already on ngcc.dev as kem-15-1.

## What we claim (and verified)

1. **Cause.** The reference `verify()` accumulates ciphertext differences into a **single byte** and
   returns `(-(uint64_t)r) >> 63` — correct, because a nonzero byte always makes `-r` set bit 63. The
   optimized `verify()` (`Optimized_Implementation/FLIT128/verify.c:38`, identical in all five AVX2
   trees) folds a 256-bit XOR accumulator into a **64-bit** `r` and returns
   ```c
   return (-(int64_t)r) >> 63;
   ```
   the sign bit of `-r`. This is `0` when `r == 0` (equal, correct), `-1` when `0 < r <= 2^63`, and
   **`0` again when `r > 2^63`** — i.e. a non-equal pair is reported EQUAL whenever bit 63 of the folded
   difference is set (with any lower bit set). The single-byte idiom was copied onto a 64-bit value.

2. **The FO re-encryption check is bypassed for a constant fraction of ciphertexts** (`logs/run.txt`,
   step [1]). Over 200000 ciphertexts obtained by flipping 1–4 random bits of a valid one, the
   optimized `verify()` calls **~3.4%** EQUAL; every reference tree calls **0%**. Exhaustive single-bit
   flips are always rejected (one bit sets at most bit 63, giving `r = 2^63`, which is rejected) — which
   is why self-tests and KATs never expose it: honest ciphertexts re-encrypt equal (`r = 0`), so the
   optimized KATs match the reference ones.

3. **This turns decapsulation into a plaintext-checking oracle** (`logs/run.txt`, step [3]). In
   `crypto_kem_dec`, `verify()` feeds `cmov(kr, z, SEEDBYTES, fail)`. When `verify()` wrongly returns 0,
   `kr` is not overwritten with the reject secret `z`, so the shared secret is the *accept-path* value
   ```
   ss = KDF( G(m' || H(pk))[0..SEEDBYTES] || H(ct) ),   m' = Dec(sk, ct),
   ```
   a public function of the decrypted message and the ciphertext. Our tool takes invalid (2–3 bit
   mauled) ciphertexts that `verify()` accepts and shows the decapsulation output equals this value
   recomputed from `pk`, `ct'` and `m'` using the scheme's own `G`/`H`/`KDF`: the prediction for the
   **correct** `m'` matches, a **wrong** `m'` does not (5/5 accepted samples). An attacker guessing `m'`
   therefore learns whether `Dec(ct') = m'`. A plaintext-checking oracle on an NTRU/RLWE KEM recovers the
   secret key by the standard adaptive chosen-ciphertext method. We demonstrate the oracle; we did not
   run the full key-recovery loop.

4. **Controls** (`logs/run.txt`).
   - `ref128`, `ref256` (unmodified reference): 0% accept (step [1]); `verify()` returns `1` on
     mismatch and `cmov` moves the whole byte (step [2]).
   - `fix128` (optimized tree + `patches/verify-fix.patch`, a constant-time nonzero fold
     `return (uint8_t)((r | (0 - r)) >> 63);`): 0% accept.

5. **Subordinate second defect** (`logs/run.txt`, step [2]). The mismatch return is `-1`, not `1`. The
   AVX2 `cmov` mask is `_mm256_set1_epi8((char)-b)`; for `b = 0xFF` this is `(char)-0xFF = 0x01`, so on
   the correctly rejected path only **bit 0** of each key byte is taken from `z` (`AA.. -> AB..`). This
   corrupts the reject key but is not the security break; the break is the accept-on-invalid in (1).

## Run it

```sh
REF=/path/to/FLIT/Implementations ./run_all.sh
```
`REF` is the submission's `Implementations/` directory (Reference_, Optimized_, Additional_). Nothing in
`REF` is modified: trees are copied into `./work/` and the fix control is patched onto the copy only.
Runtime ~2–3 min. Requires `gcc` with AVX2.

- `src/flit_fo_tool.c` — one tool, compiled against each submitted tree (its own `crypto_kem_*`,
  `indcpa_dec`, `verify`, `cmov` and hash macros). Modes: `honest`, `acc`, `ct`, `pco`.
- `patches/verify-fix.patch` — the constant-time fix, used only for the `fix128` control.
- `logs/run.txt` — our run against the archived NICCS package.

This analysis was prepared with AI assistance; every result comes from running the submitted code.
