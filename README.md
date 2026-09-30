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
| `scloudplus-reencryption-timing` | Scloud+ | KEM | B (side-channel) | decapsulation time depends on the decrypted message: the FO re-encryption BD6/BD12 rejection sampler consumes a message-dependent number of XOF squeezes (L256 296-301 batches/53-54 squeezes, L384 555-561/99-100, L512 800-807/189-191); ~4.6k cyc/squeeze, ~0.9k/batch, class gap ~6k (host-dependent); kem-30-1/PolarLAC analogue, no key recovery; the Barnes-Wall decoder and rest of decaps are constant-time (div=0/cmov=0) |
| `facto-dsa-forgery` | Facto-DSA | SIG | A | public-key-only forgery at level 128 accepted by the genuine verifier (correct reject controls); levels 256/512 are bounded extrapolations (OOM), NOT completed |
| `chinith-em-misalignment` | Chinith (uBlockith-EM) | SIG | A (spec, certificational) | one-block misalignment of the OWF constraint chain (spec p.68/69 + code): honest EM signatures rejected once a_tilde_0 is bound (0/5 -> 5/5 with a one-block shift); in the spec as written pk2 never enters the relation and forgery reduces to a 2-round fixed point findable at ~2^135.5 vs claimed 256 (extrapolated per-guess cost; spec-literal only, the shipped code binds pk2) |
| `flextree-signature-malleability` | FlexTree | SIG | A (spec; sEUF-CMA only) | strong forgery: from any honest signature, a public-key-only attacker rewrites the unchecked PORS+FP auth-node zero padding (spec Sec. 1.10) into sigma' != sigma on the same message, accepted by the unmodified crypto_sign_open at all 8 sets, Reference + Optimized; EUF-CMA (fresh-message forgery) NOT claimed |
| `ops-sig-spec-sampler-forgery` | OPS-SIG | SIG | A (spec, certificational) | public-key-only forgery accepted by a **spec-conformant** verifier: spec SampleInBall (Alg.6) fixes the challenge support {n-tau..n-1} -> challenge space 2^tau (39/45/90 vs claimed 234/261/525); completed at toy tau with reject controls, real L1 = 2^39 (extrapolated); also spec Decompose/UseHint (Alg.30/32) wrap ceil(q/alpha) -> 7.5/31.5/67.0% honest-verify failure. The shipped reference binary is correct and KAT-consistent (spec<->code discrepancy) |
| `afs-kex-auth-binding` | AFS-KEX (pMAKE-BW) | KEX | A (spec; outside the paper's model) | replayable initiator credential (cpk_A, seed_A) => impersonation after a responder-side encapsulated-key leak; public-key-copy unknown-key-share (K_SESSION=PRF(K_A,K_B), identities in no KDF/MAC); decapsulation failure oracle open to an unauthenticated peer; 200/200 x3 levels with passing controls. Refutes the authors' 2026-09-22 forum claim; independent of the acknowledged wrapper reuse (ngcc.dev kex-02-1). No MLWE break; findings sit outside the Sec 8-9 model |
| `rudraksh2-symmetric-cap` | Rudraksh2 | KEM | A (category shortfall, demonstrated) | the 512 sets (claimed classical 512 / quantum 256) have only 256-bit symmetric strength: the SM3-based XOF has a 256-bit chaining value and lenK=64 B = one SM3 block, so the secret key AND the session key are functions of a single 256-bit chaining value (rebuilt 50/50 exact from the unmodified keygen/encaps) => ~2^256 classical / ~2^128 Grover, short of 512/256 by 256/128 bits; 256 sets meet exactly, 128 sets' quantum-80 is unbacked by a 128-bit message (2^64 Grover, depth-dependent). Also (B) Cortex-M4 128/256 use MINAL_BETA=0 vs spec/ref 220: KAT mismatch, 0/200 interop with ref, one-line fix restores both; and (spec) all -II sets use q=4001 with 2n∤(q-1), so the spec-mandated primitive 2n-th root / negacyclic NTT does not exist (nttcheck.py; consistent with no -II impl shipped) and 128-II is ~5 bits below ML-KEM-512; and (low) kem_dec/kem_enc ignore the caller-declared length => OOB read (ASAN, kem-14-1 class, read not write). The 2^256/2^128 search is NOT run; the reduction to a 256-bit value is the claim. Refuted angles (recorded): decoder is ML-optimal, decode path is constant-time, no ciphertext malleability |

Severity A = fundamental (full key recovery / forgery / semantic-security break). `A*` =
category/claim mismatch backed by a working full key recovery (see the package README).

## Implementation-level packages (severity B)

Kept separately from the design-level packages above because each backs a public comment that
cites a reproduction package. They contain no key recovery.

| repo | scheme | category | severity | one-line claim |
|---|---|---|---|---|
| `yuanyang-dsa-sampler-constant` | YuanYang.DSA | SIG | B (implementation) | -512 wide-sampler rejection constant is 1/(2(16η)²) instead of 1/(2(4η)²): the signature mean becomes (0.458/4)·Â·(𝟙,𝟙), a linear function of the secret Gram root (10σ secret-dependence at 4·10⁵ signatures, cross-key controls at noise); with the public covariance bug this exposes f f̄+g ḡ (the FKTWY EUROCRYPT 2020 quantity); exact recovery projected at ~2³⁵ signatures by simulation only; NO key recovery performed |
| `weaver-bch-decoder` | Weaver | KEM | B (implementation) | Berlekamp–Massey discrepancy loop `j <= i+1` mis-decodes some ≤t-error patterns (W-1024 t=4: 0.39–1.66% at e=4; W-2048 t=7: 0.2–3%), still present at GitHub ca99d0f; one-line fix, KATs unchanged; submitted W-1024 (no high-layer BCH decode) has real DFR ≈2^-45.5–2^-47.5 vs claimed 2^-231.7 (exact model validated on 3·10⁸ coefficients); failure-boosting cost table only, NO key recovery |

## Design-level comment package (certificational)

| repo | scheme | category | severity | one-line claim |
|---|---|---|---|---|
| `uvw-kem-dfr-reaction` | UVW-KEM | KEM | certificational (design) | the 1000-retry decoder leaves an overall DFR of 2^-43.3/-42.1/-41.7 (exact counting; A=1 reproduces spec Thm 2), and failures occur only on hidden pairs: a failure-only reaction (no timing, single status, implicit rejection) recovers all 430 UVW-128 pairs/ratios from 1000 failures (~2^53 queries) in simulation, so the kem-38-2 constant-time fix is not sufficient; reaching 2^-128 needs ~10^7 retries. Structure recovery after the pairs follows the 9-24 forum post and is NOT rerun; 256/512 extrapolated. Also: per-retry memory leaks (ASan) and a shared DRNG consumed by decapsulation |
| `niike-pk-validation` | NIIKE | KEX | A (protocol; demonstrated) | NO public-key validation: `decode_bundlevertex` discards the `fp_decode` canonicality flag at all 15 call sites and `kex_derive_ss` returns 0, so an all-zero / non-canonical / random peer public key is accepted (rc=0) and the shared secret is `00..0`, INDEPENDENT of the victim's static key (lv128 and lv256) — an active peer learns the session key. Plus NGCC-III is non-functional: hard-coded lv512 key (KAT `Seed` 10/10 distinct but `SK/PK/SS` 1/10; RNG commented out) and `assert(top==0)` aborts it in the default build; the lv512 code prime (16394-bit, 7 mod 8) differs from the spec §5.5 prime (16392-bit, 3 mod 8, which violates the spec's own §5.3), and only lv128/lv256 KATs reproduce byte-for-byte. No break of the group action; underlying assumption NOT attacked |

## How to build a package

```
cd <repo>
# read the README for the exact variable name and reference sub-directory layout
REF=/path/to/Reference_Implementation/<scheme-level> ./run_all.sh     # or REFROOT=...
```

Every package excludes compiled binaries and any vendor reference code; only our attack/
verification sources, the honest README, the build script, and real run logs are included.
