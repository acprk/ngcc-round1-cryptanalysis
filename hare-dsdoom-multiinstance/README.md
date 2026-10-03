# HARE: same-key multi-instance decoding (DS-DOOM) puts HARE-256/384/512 below their claimed classical level

A **design-level** finding on **HARE** (ICCS NGCC round-1 code-based KEM, `kem-16`, HQC family). Every
encapsulation under one static public key publishes, **uncompressed**, a fresh syndrome
`u = r1 + h*r2 mod X^n-1` with `|r1| = |r2| = wr` and the **same** `h` (vendor `ref/hqc.c:115-121`,
`ref/data_structures.h:18-23`). `Q` ciphertexts under one key are therefore `Q` instances of one
quasi-cyclic SD problem `[2n, n, 2wr]`, each with `n` cyclic shifts, i.e. `M = n*Q` targets for one
Decoding-One-Out-of-Many run. Solving any one of them gives `r2`, hence `m` (decode
`Decompress(v) - Trunc(s*r2)`), hence that session's `K = G(H(ek) || m || salt)`.

Spec Sec. 7.3.3 accounts for DOOM only *within* one instance (the `O(sqrt n)` gain from the `n` shifts);
the gain from many ciphertexts under one key is not accounted for, and the IND-CCA2 bound (Theorem 10)
is single-challenge. NGCC sets no per-key ciphertext limit for KEMs; the evaluation ceiling is 2^80.

Costs below are from the **unmodified official estimator** of May & Sa Diogo, *Multi-Instance Security
Degradation of Code-Based KEMs*, ePrint 2026/517 (`doom.py`, github.com/Gabsadio/Multi-Instance-KEM @
`39b78dcc`), the same file and commit that reproduces ngcc.dev **kem-05-2** (BIKE-MLThre) bit-for-bit
(`[cal]`: 127.890 / 96.189 and 255.780 / 103.648).

| shipped set | spec alias | claimed | first `Q` below claim | T (mem) at that `Q` | T (mem) at `Q = 2^80` |
|---|---|---|---|---|---|
| HARE-128 | HARE-2 | 128 | none up to 2^80 | -- | 2^148.5 (2^108.7) |
| HARE-256 | HARE-5 | 256 | **2^72** | 2^255.43 (2^103.4) | **2^252.99** (2^111.4) |
| HARE-384 | HARE-7 | 384 | **2^64** | 2^383.17 (2^97.4) | **2^376.57** (2^113.4) |
| HARE-512 | HARE-9 | 512 | **2^76** | 2^511.69 (2^110.8) | **2^509.69** (2^114.8) |

Spec Table 2 also lists HARE-1 (128) and HARE-3 (192), which are **not** in the submitted implementation
package (its README: only HARE-2/5/7/9 are shipped). For completeness: HARE-1 first drops below 128 at
`Q = 2^66` (2^127.76), HARE-3 below 192 at `Q = 2^78` (2^191.59); 192 is not an NGCC target level.

## What is completed vs. estimated

- **Completed on the real implementation (all 4 shipped sets, 20 trials each, `[e2e]`):**
  official `crypto_kem_enc` output is reproduced byte-for-byte; `u == r1 + h*r2` with
  `|r1| = |r2| = wr` (one SD instance per ciphertext, `h` fixed by `pk`); for a random shift `j`,
  `X^j * (r1, r2)` solves `X^j * u` with the same weights (the `rot = n` factor the estimator uses);
  from `pk`, `ct` and a decoder output `(r1, r2)` alone, the attacker decodes `m` and recomputes the
  session key equal to the one `crypto_kem_dec(sk)` returns; a wrong decoder output (one bit of `r2`
  moved) fails the public syndrome test, so success is publicly checkable.
- **Estimated, not run:** the decoding search itself (`2^{252+}` work). Its cost comes only from the
  official estimator. The decoder output in `[e2e]` is re-derived from the encapsulation randomness
  (marked `ORACLE` in `src/e2e.c`); `sk` is used only to score the recovered key (`SCORING`).

## Caveats (please read)

- **Margins are thin**: 0.57 / 0.83 / 0.31 bits at the first crossing, 3.0 / 7.4 / 2.3 bits at `Q = 2^80`.
  The result is "a concrete attack below the claimed level under the pinned 2026/517 estimator",
  the same standard as ngcc.dev kem-05-2 and kem-32-2, not a large break.
- **Memory** is 2^97-2^115 bits, the same order as what ngcc.dev accepted for kem-05-2 (2^96.2 / 2^103.6).
- **Code dimension**: we use `k = n - 2` (as for TriQ-KEM); `k = n` and `k = n - 1` change `T` by at
  most 0.02 bit (`k-sensitivity` lines).
- **Conservative start point**: at `Q = 1` the DS-DOOM estimate (e.g. 2^411.4 for HARE-384) is *above*
  the spec's own BJMM figure for the ciphertext problem (Table 4, 3-DUQCSD-PT: 387). A multi-instance
  BJMM-type decoder would likely do better; we do not claim that.
- The estimator's optimum is not perfectly monotone in `Q` (grid of discrete parameters), e.g.
  HARE-1 at `2^78` vs `2^80`; we report what it prints.

## Run

```
REFROOT=/path/to/HARE_Code_Package ./run_all.sh          # ~1-2 min, single core
```

`REFROOT` is the unmodified vendor package root (contains `Implementations/`, `Self_Evaluation/`,
`Test_Vectors/`; check it with the vendor `MANIFEST.sha256`). The vendor code is compiled in place and
never modified or redistributed. `doom.py` is cloned from its public repository at the pinned commit.
Needs `gcc`, OpenSSL `libcrypto`, `git`, Python 3 with the packages `doom.py` imports (`numpy`, `scipy`).
`TRIALS=` sets the `[e2e]` trial count. Our output: `results/run_all.log`.

| step | file | what it shows |
|---|---|---|
| `[kat]` | vendor `verify_kat_kem.c` | our build line replays all 4 vendor KAT files |
| `[cal]` | `src/calib_kem05_2.py` | official `doom.py` = ngcc.dev kem-05-2 exactly |
| `[est]` | `src/hare_dsdoom.py` | HARE costs vs `Q`; `n`, `wr` read from vendor `parameters.h` |
| `[e2e]` | `src/e2e.c` | everything except the search, on the real implementation |

## Suggested fixes

Raise `n`/`wr` so that the ciphertext problem keeps its target under `Q = 2^80` same-key instances
(as ngcc.dev asked of BIKE-MLThre in kem-05-2), or state and enforce a per-key encapsulation limit and
account for the multi-instance gain in Sec. 7.3.3.

This analysis was prepared with AI assistance; every number above is printed by `run_all.sh`.
