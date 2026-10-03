# trike-unsalted-multitarget — TRIKE (kem-36): unsalted deterministic FO, multi-ciphertext search below the claimed level for TRIKE-5 and TRIKE-9

Verification code for our follow-up comment on **TRIKE**. On 2026-10-02, ngcc.dev kem-36 (36-1 to 36-6)
did not list this issue. The forum thread had only our 2026-10-01 comment, which does not cover it.
No vendor code is included or modified. Point `REFROOT` at the submission's
`Implementations and Test_Vectors/Implementations/Reference_Implementation`. We supply only
`get_random_number()`. The submitted `kem_keygen` / `kem_enc` / `kem_dec` are used unmodified.

## The issue

Spec §1.4.3, Algorithm 5: `m ← {0,1}^l`, `(e0,e1,e2) ← H4(m, r2)`, `u = e0 + e1 r1 + e2 r2`,
`v = e0 + e1 t1 + e2 t2`, `c = (u, v, m + L(e))`, `K = K(m, c)`. The only fresh randomness is `m`. There is no
salt, and `(c, K)` is a deterministic function of `(pk, m)`. The code matches this:
`KEM_AlgorithmInstance.c:245` is the only global-RNG read in `kem_enc`. The error vector comes from a DRNG
seeded with `(m, r2)` (`sample.c:230-242`).

An attacker collects `T` ciphertexts sent to one static public key and enumerates `m`. Each guess is
re-encrypted once and looked up among all `T` ciphertexts. A hit gives that session's `K`. The expected cost
is `2^l / T` encryptions, and the memory is `T` entries. This is the multi-ciphertext attack against
FrodoKEM-640 and HQC-128 (FrodoKEM annex 2023, credited to R. Perlner; Glabush–Hövelmanns–Stebila,
ePrint 2025/343). Those schemes fixed it with a public salt, and so did TRIKE's QC-code siblings QUBE and
TriQ-KEM in this call. TRIKE has no salt.

| set | l | claimed classical | T = 2^64 | T = 2^80 | below claim? |
|---|---|---|---|---|---|
| TRIKE-2 | 256 | 128 | 2^192 | 2^176 | no |
| **TRIKE-5** | 256 | 256 | **2^192** | **2^176** | **yes, by 64 / 80 bits** |
| TRIKE-7 | 512 | 384 | 2^448 | 2^432 | no |
| **TRIKE-9** | 512 | 512 | **2^448** | **2^432** | **yes, by 64 / 80 bits** |

Costs are in encryptions. One encryption is about `2·t·r` bit operations: about 2^25 for TRIKE-5 and 2^28 for TRIKE-9.
This does not close the gap: at T = 2^80 the totals are about 2^201 and 2^460.

## What `run_all.sh` checks (scaled: only the low B bits of m are nonzero)

- Every `kem_enc` reads the global RNG exactly once, with width `PARAM_M`. The shim aborts otherwise.
  Therefore `m` is the only per-ciphertext randomness of the submitted code.
- The attacker uses only `pk` and the `T` ciphertexts. At every hit, the full ciphertext matches, and the
  recovered key equals both the encapsulator's key and the output of `kem_dec(sk, c)`. Victim keys are used
  for SCORING only.
- The `1/T` law. TRIKE-5 (full r = 35363), B = 10, T = 1..32, 24 trials each (`logs/fit.txt`):

  ```
  OLS log2(work) = 10.04 + (-1.002)*log2(T+1)   [theory: 10 - log2(T+1)]
  ```
  The other runs: TRIKE-5 at B = 13, T = 64 gave a mean of 1.11× the expectation. TRIKE-9 (r = 114043) at
  B = 8, T = 4 gave 1.00×. TRIKE-2 at B = 10, T = 4 gave 0.75× (same mechanism, but not below its claim).
  Every session key matched.

Only the full-size `2^176` / `2^432` searches were not run.

## Run

```
REFROOT=".../Implementations and Test_Vectors/Implementations/Reference_Implementation" ./run_all.sh
```
The script runs 9 single-core jobs in parallel, about 10 minutes wall time. It writes `out/` and records the
sha256 of the linked submission files. `logs/` holds our runs (gcc 9.5.0, x86-64).
