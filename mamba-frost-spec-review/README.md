# mamba-frost-spec-review — MAMBA-Frost (kem-20): unsalted specified Encaps, and a 2^64 Grover margin at Frost-128

This is the verification code for our Round-1 comment on **MAMBA-Frost**. On 2026-10-01, ngcc.dev listed no
vulnerability finding for kem-20, and the forum thread had no replies. No vendor code is included or
modified. Point `REFROOT` at the submission's `API_PKC/Implementations/Reference_Implementation`.
In every experiment we supply only `randombytes()`, and the submitted `crypto_kem_*` functions are used unmodified.

## 1. The specified Encaps is unsalted (specification only, not the submitted code)

Spec Alg. 7 (PDF p. 9) derives every encryption coin, including the ciphertext-dither seed µ, from
`G_FO(h_pk ‖ M)`. The 32-byte "salt" in the ciphertext is the serialization of µ (PDF p. 23), and
`κ_m = λ`. Encaps is therefore deterministic in `(pk, M)`. Given `T` ciphertexts to one static key, an
attacker enumerates `M`, re-encrypts once, and looks the result up among all `T` ciphertexts. One session
key then costs about `2^λ / T`. This is the multi-ciphertext attack that led FrodoKEM to add its salt
(FrodoKEM annex 2023-04-18, Sec. 2, credited to R. Perlner). The appendix B.4 proofs depend on this unsalted
derivation. The submitted `kem.c` draws `M ‖ salt` at random and hashes `G(pkh ‖ M ‖ salt)`, so it is
**not** affected. The specification and its proofs describe a different KEM from the one the KATs define.

`src/multict.c` (scaled) supplies `M` (16 bits) and `salt = SHAKE(0xEE ‖ h_pk ‖ M)` as the
randomness. This reproduces the determinism of Alg. 7. One static key receives `T = 64` ciphertexts,
and the attacker sees only `pk` and the ciphertexts.

| mode | runs | session key recovered | encryptions to first hit | expected |
|---|---|---|---|---|
| spec Alg. 7 (unsalted) | 8 | 8/8 | mean 809 | 2^16/65 ≈ 1008 |
| submitted code (fresh public salt), control | 3 | 3/3 | 2565 / 44305 / 44743 | 2^16·64/65 ≈ 64527 |

In every run, the key of a different ciphertext does not match (control). With the salt, each guess
must be re-encrypted once per ciphertext, so the factor `T` disappears. The control has few runs and
high variance, because the first hit is the minimum of `T` uniform values. The full-size cost is
`2^128 / T` at Frost-128, e.g. `2^88` at `T = 2^40`, and was **not** run.

## 2. Frost-128: about 2^64 Grover iterations against the 80-bit quantum target (the kem-34-1 pattern)

At Frost-128, `κ_m = 128`, and the salt is public in `ct`. A candidate `M` can therefore be tested
publicly: re-run the submitted `crypto_kem_enc` with randomness `M ‖ salt(ct)` and compare the result to
`ct`. This uses neither `sk` nor a decapsulation oracle. A generic Grover search needs about `2^64` oracle
iterations, below the 80-bit quantum target that NGCC sets for the 128 level. As in ngcc.dev kem-34-1, this
is a parameter-analysis gap, not a demonstrated break: the oracle has to implement the full encryption,
and we give no gate-level cost. Frost-256/384/512 (`κ_m` = 256/384/512) meet their 128/192/256 quantum
targets exactly.

`src/pubcheck.c`: for Frost-128/256/512, `check(true M) = 1` and returns the honest session key, and
`check(M⊕1) = 0` (`logs/grover_pubcheck.log`). The `M` of the honest encapsulation is recorded only to
have a known-true candidate (SCORING).

## Run

```
REFROOT=/path/to/API_PKC/Implementations/Reference_Implementation ./run_all.sh          # ~3 min
REFROOT=... ./run_all.sh salted                                                          # + ~80 min control
```

`logs/` holds our runs (gcc 11.4.0, x86-64). The victim's keys and session keys are used only for scoring
(`grep SCORING src/*.c`).
