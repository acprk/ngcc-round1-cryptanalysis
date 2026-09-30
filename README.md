# NGCC Round-1 verification packages

Self-contained **verification / attack** source packages for the findings of an authorized public
evaluation (cryptanalysis) of ICCS **Next-Generation Commercial Cryptography (NGCC)** round-1
submissions. Each subfolder is an independent repository: our attack/verification code, an honest
README, and a `run_all.sh` / `Makefile` / `build.sh` that builds against the vendor reference via a
`REF=` (or `REFROOT=`) variable.

## Disclaimer

- **Authorized public evaluation.** These artifacts support responsible, public cryptanalysis of
  publicly-submitted schemes.
- **Reference implementations are NOT included.** We do **not** redistribute any submitter's code.
  Obtain each vendor reference implementation from the ICCS submission package and point `REF=` /
  `REFROOT=` at it (see each package's README).
- **Attacks use only public data.** Each attack reads only public inputs (public keys, ciphertexts,
  signatures, KAT vectors). Where a secret key appears, it is used **only for scoring** (to report
  how many coefficients were recovered / to confirm a forgery), never to guide the attack; every
  such use is marked in-source (`grep` for `SCORING` / `[ground truth]` / `SK-READ`).
- **Timings** are on a **104-core / 251 GB** machine, core-pinned with `taskset` where timing matters.
## The packages

These are the design-level (severity A) findings. Most accompany the eprint report
<https://eprint.iacr.org/2026/2232>; `afs-kex-auth-binding` is a standalone protocol-layer
finding accompanying a public forum comment (not part of that eprint). Implementation-level
(severity B) findings have been removed from this repository, with one exception listed in its own
section below that backs a public comment.

| repo | scheme | category | severity | one-line claim |
|---|---|---|---|---|
| `shuttle-key-recovery` | Shuttle | SIG | A | full secret-key recovery (768/1536/3072) + forgery accepted by the unmodified verifier; sign-alignment second-moment leak in the abort-free sampler; 12.7-52.7 min single-core |
| `bit-key-recovery` | BiT | SIG | A | full key recovery (768/768) + accepted forgery from honest transcripts; bimodal sign shared across response blocks; ~7 min end-to-end |
| `mamba-nike-key-recovery` | MAMBA-NIKE | KEX | A* | static-key recovery from unvalidated reconciliation; 71 queries ONLY under the reference's -DSTATISTICAL_TEST build, ~2^15 against the deployed API (asserted); 128/384 reliable, 192 ~60% |
| `loongkem-subring-projection` | LoongKEM | KEM | A | IND-CPA (decision) break by sub-ring projection over a reducible ring; ~2^77/2^107/2^208 vs claimed 128/384/512; full original-key recovery out of reach and NOT claimed |
| `cheetahkem-subring-projection` | CheetahKEM | KEM | A | IND-CPA break ~2^53.4 by sub-ring projection (X^640+1 splits); full key recovery NOT achieved (real-scale sieve precision failure); toy pipeline validates |
| `origami-pk-forgery` | Origami | SIG | A | public-key-only universal forgery accepted by the unmodified verifier at all sets |
| `polarkem-keyless-decapsulation` | Polar-KEM | KEM | A | keyless decapsulation (10/10 x3); the "secret" isometry is regenerated from a public seed |
| `facto-dsa-forgery` | Facto-DSA | SIG | A | public-key-only forgery at level 128 accepted by the genuine verifier (correct reject controls); levels 256/512 are bounded extrapolations (OOM), NOT completed |
| `chinith-em-misalignment` | Chinith (uBlockith-EM) | SIG | A (spec, certificational) | one-block misalignment of the OWF constraint chain (spec p.68/69 + code): honest EM signatures rejected once a_tilde_0 is bound (0/5 -> 5/5 with a one-block shift); in the spec as written pk2 never enters the relation and forgery reduces to a 2-round fixed point findable at ~2^135.5 vs claimed 256 (extrapolated per-guess cost; spec-literal only, the shipped code binds pk2) |
| `flextree-signature-malleability` | FlexTree | SIG | A (spec; sEUF-CMA only) | strong forgery: from any honest signature, a public-key-only attacker rewrites the unchecked PORS+FP auth-node zero padding (spec Sec. 1.10) into sigma' != sigma on the same message, accepted by the unmodified crypto_sign_open at all 8 sets, Reference + Optimized; EUF-CMA (fresh-message forgery) NOT claimed |
| `afs-kex-auth-binding` | AFS-KEX (pMAKE-BW) | KEX | A (spec; outside the paper's model) | replayable initiator credential (cpk_A, seed_A) => impersonation after a responder-side encapsulated-key leak; public-key-copy unknown-key-share (K_SESSION=PRF(K_A,K_B), identities in no KDF/MAC); decapsulation failure oracle open to an unauthenticated peer; 200/200 x3 levels with passing controls. Refutes the authors' 2026-09-22 forum claim; independent of the acknowledged wrapper reuse (ngcc.dev kex-02-1). No MLWE break; findings sit outside the Sec 8-9 model |

Severity A = fundamental (full key recovery / forgery / semantic-security break). `A*` =
category/claim mismatch backed by a working full key recovery (see the package README).

## Implementation-level package (severity B)

Kept separately from the eight design-level packages above because it backs a public comment that
cites a reproduction package. It contains no key recovery.

| repo | scheme | category | severity | one-line claim |
|---|---|---|---|---|
| `yuanyang-dsa-sampler-constant` | YuanYang.DSA | SIG | B (implementation) | -512 wide-sampler rejection constant is 1/(2(16η)²) instead of 1/(2(4η)²): the signature mean becomes (0.458/4)·Â·(𝟙,𝟙), a linear function of the secret Gram root (10σ secret-dependence at 4·10⁵ signatures, cross-key controls at noise); with the public covariance bug this exposes f f̄+g ḡ (the FKTWY EUROCRYPT 2020 quantity); exact recovery projected at ~2³⁵ signatures by simulation only; NO key recovery performed |

## How to build a package

```
cd <repo>
# read the README for the exact variable name and reference sub-directory layout
REF=/path/to/Reference_Implementation/<scheme-level> ./run_all.sh     # or REFROOT=...
```

Every package excludes compiled binaries and any vendor reference code; only our attack/
verification sources, the honest README, the build script, and real run logs are included.
