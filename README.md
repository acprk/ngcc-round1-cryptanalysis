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
## The 16 packages

| repo | scheme | category | severity | one-line claim |
|---|---|---|---|---|
| `shuttle-key-recovery` | Shuttle | SIG | A | full secret-key recovery (768/1536/3072) + forgery accepted by the unmodified verifier; sign-alignment second-moment leak in the abort-free sampler; 12.7-52.7 min single-core |
| `bit-key-recovery` | BiT | SIG | A | full key recovery (768/768) + accepted forgery from honest transcripts; bimodal sign shared across response blocks; ~7 min end-to-end |
| `oaep-ntru-attack` | OAEP-NTRU | KEM | B | one-query IND-CCA2 break (1000/1000 x3); non-canonical coefficient encoding + reject-path key leak; ~0.3/0.8/2.1 s for n=648/1296/2592 |
| `qimen-pike-malleability` | QIMEN-PIKE | KEM | B | one-query CCA (add-p, 8/8 at 3 levels) + hint-triggered SIGSEGV DoS; non-canonical ciphertext encoding |
| `bra-brqc-padding-malleability` | BRA & BRQC | KEM | B | one-query CCA via unbound padding bits (BRA 2^10; BRQC 2^14/2^10/2^2) |
| `aigis-enc-attack` | Aigis-Enc+ | KEM | B | full decryption oracle (300/300) + PC oracle (600/600 x3); inert FO re-encryption check (ss written before the check; dead cmov) |
| `amoeba-df-oracle-key-recovery` | Amoeba | KEM | B | full key recovery (517/517, ~5700 queries) + SIGABRT DoS; pre-FO decryption-failure oracle; ~4 s wall (~1.2 s CPU) |
| `mamba-nike-key-recovery` | MAMBA-NIKE | KEX | A* | static-key recovery from unvalidated reconciliation; 71 queries ONLY under the reference's -DSTATISTICAL_TEST build, ~2^15 against the deployed API (asserted); 128/384 reliable, 192 ~60% |
| `loongkem-subring-projection` | LoongKEM | KEM | A | IND-CPA (decision) break by sub-ring projection over a reducible ring; ~2^77/2^107/2^208 vs claimed 128/384/512; full original-key recovery out of reach and NOT claimed |
| `cheetahkem-subring-projection` | CheetahKEM | KEM | A | IND-CPA break ~2^53.4 by sub-ring projection (X^640+1 splits); full key recovery NOT achieved (real-scale sieve precision failure); toy pipeline validates |
| `origami-pk-forgery` | Origami | SIG | A | public-key-only universal forgery accepted by the unmodified verifier at all sets |
| `polarkem-keyless-decapsulation` | Polar-KEM | KEM | A | keyless decapsulation (10/10 x3); the "secret" isometry is regenerated from a public seed |
| `facto-dsa-forgery` | Facto-DSA | SIG | A | public-key-only forgery at level 128 accepted by the genuine verifier (correct reject controls); levels 256/512 are bounded extrapolations (OOM), NOT completed |
| `uvw-always-accept` | UVW | SIG | B | verifier runs the full check then discards the verdict and returns accept -> universal forgery; verify ~0.2 s (the check still runs) |
| `tins-key-recovery` | Tins | SIG | B | witness/key recovery from ONE signature (GGM child seeds ignore the parent) + accepted forgery at 256; 128/512 obstructed by level-specific reference defects |
| `cmultiurag-decaps-dos` | C-Multi-UR-AG | KEM | B | decapsulation SIGSEGV DoS via unsigned-degree underflow; ~74% single-bit-flip crashes at level 256, 0% at 128/512; ~0.6 s per faulting decap |

Severity A = fundamental (full key recovery / forgery / semantic-security break); B = serious
implementation defect (one-query CCA / decryption oracle / DoS). `A*` = category/claim mismatch
backed by a working full key recovery (see the package README).

## How to build a package

```
cd <repo>
# read the README for the exact variable name and reference sub-directory layout
REF=/path/to/Reference_Implementation/<scheme-level> ./run_all.sh     # or REFROOT=...
```

Every package excludes compiled binaries and any vendor reference code; only our attack/
verification sources, the honest README, the build script, and real run logs are included.
