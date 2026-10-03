# Qing Luan: multi-pipe SM3 (second-)preimage overclaim, and a secret-dependent η re-expansion trace

Two observations on **Qing Luan** (ICCS NGCC round-1, `sign-20`). Neither is a break of a parameter set.

- **[A] design / proof gap.** The multi-pipe hash `H_w(m) = SM3(0‖m) ‖ … ‖ SM3(P−1‖m)`, with P = ⌈2λ/256⌉,
  is claimed to have (second-)preimage resistance 2^{2λ} (spec §1.5.2 p.4, §2.4.1 p.12; `security-argument.md`
  §3.3: "Joux does not break second preimage"). Joux multicollisions break this for any concatenation of
  Merkle–Damgård hashes. A generic attack costs about **2^{(P−1)·256}**, one pipe less than claimed. The
  message-binding term of Theorem 1 (p.14) inherits the error. Every level still meets its classical target,
  but **Qing Luan-256 has zero margin** (2^256 = 2^256).
- **[C] side-channel, no η leakage.** Every signature re-expands the secret η from `Seed_e` with a
  variable-length rejection sampler. The draw count is a deterministic, repeatable function of the secret
  seed. It is measurably uncorrelated with η, and theory says it is independent of η. Spec §1.7 (p.6) calls
  this step "constant-time".

Source permalinks (ngcc-harness copy, byte-identical to the ICCS archive):
[`hash.c:215` hash_final, one SM3 per pipe](https://github.com/ngcc-dev/ngcc-harness/blob/0b3c3521458e96942a9dee99c9d85b13e78d5d61/sign-20/Implementations%20and%20Test_Vectors/Implementations/Reference_Implementation/QingLuan-512/src/hash.c#L215) ·
[`mpc.c:186-208` digest_Msg = H_w(0x0A‖Salt‖pk_hash‖Msg)](https://github.com/ngcc-dev/ngcc-harness/blob/0b3c3521458e96942a9dee99c9d85b13e78d5d61/sign-20/Implementations%20and%20Test_Vectors/Implementations/Reference_Implementation/QingLuan-512/src/mpc.c#L186-L208) ·
[`sign.c:54-57` ExpandSK on every signature](https://github.com/ngcc-dev/ngcc-harness/blob/0b3c3521458e96942a9dee99c9d85b13e78d5d61/sign-20/Implementations%20and%20Test_Vectors/Implementations/Reference_Implementation/QingLuan-512/src/sign.c#L54-L57) ·
[`rsdp.c:68-76` rsdp_csprng_fz](https://github.com/ngcc-dev/ngcc-harness/blob/0b3c3521458e96942a9dee99c9d85b13e78d5d61/sign-20/Implementations%20and%20Test_Vectors/Implementations/Reference_Implementation/QingLuan-512/src/rsdp.c#L68-L76) ·
[`rsdp.c:103-111` rsdp_gen_secret_exp](https://github.com/ngcc-dev/ngcc-harness/blob/0b3c3521458e96942a9dee99c9d85b13e78d5d61/sign-20/Implementations%20and%20Test_Vectors/Implementations/Reference_Implementation/QingLuan-512/src/rsdp.c#L103-L111)

## [A] What is measured

`joux/joux_secondpreimage.py` is a faithful scaled model. It has P pipes. Each pipe is a Merkle–Damgård
chain over an n0-bit chaining value, with compression `trunc_n0(SHA-256(byte(p)‖chain‖block))`, and pipes are
separated by a 1-byte prefix exactly as in `hash.c`. The scaling law depends only on the MD structure and the
concatenation, not on the compression function. For P = 2, 3, 4 and every tested n0, the script finds a
verified second preimage M′ ≠ M* (all P pipes equal). The attack builds a multicollision on pipe 0 only, steers
pipe 0 with a final block, and searches the family against the other P−1 pipes. The family size is fixed in
advance at **2^{(P−1)·n0+4}**, so success at that size is the test. Naive search needs 2^{P·n0}. Compression-call counts are in the log. The NAIVE rows are
single random runs and only confirm that a match exists; their slope is too noisy to quote.

`joux/multitarget.py` checks the multi-target term. Salt is a **prefix**, so T salts give T different IVs and
the generic ÷T speedup disappears. Measured slope of log2(calls) against log2(T): DISTINCT salts ≈ 0
(−0.15, +0.05). The SHARED-salt positive control gives ≈ −1 (−1.10, −1.25). So multi-target is no cheaper
than single-target, and no level drops below its target.

| level | P | generic (2nd-)preimage | spec §1.5.2 / Thm 1 (PDF) / security-argument.md | target | verdict |
|---|---|---|---|---|---|
| 128 | 1 | 2^256 | 2^256 / 2^192 / 2^176 | 2^128 | meets |
| 256 | 2 | **2^256** | 2^512 / 2^448 / 2^432 | 2^256 | meets, **zero margin** |
| 384 | 3 | 2^512 | 2^768 / 2^704 / 2^688 | 2^384 | meets, +128 (claimed +384) |
| 512 | 4 | 2^768 | 2^1024 / 2^960 / 2^944 | 2^512 | meets, +256 (claimed +512) |

## [C] What is measured

`ct-sampler/probe.c` links REF's **unmodified** `rsdp.c`, renaming only `xof_squeeze` so its calls can be
counted (`-Dxof_squeeze=xof_squeeze_counted`; no decision is changed). It calls `rsdp_gen_secret_exp`, the
routine `sign.c:57` runs on every signature, twice per fresh key.

| level | keys | rejections min/mean/max | identical on re-expansion | corr(rej, Σηᵢ) | corr(rej, #{ηᵢ=0}) | 5% threshold |
|---|---|---|---|---|---|---|
| 128 | 30000 | 4 / 18.2 / 40 | 30000/30000 | −0.0068 | +0.0037 | 0.011 |
| 256 | 3000 | 15 / 35.9 / 65 | 3000/3000 | +0.0127 | −0.0120 | 0.036 |
| 384 | 3000 | 30 / 52.9 / 81 | 3000/3000 | −0.0080 | −0.0330 | 0.036 |
| 512 | 3000 | 40 / 70.1 / 100 | 3000/3000 | +0.0072 | −0.0031 | 0.036 |

(L128 was rerun at 30000 keys after the 3000-key run gave +0.045 for one of its eight correlations. Both runs are in the log.)

Why there is no η leakage: each draw is one XOF byte masked to 3 bits, and it is rejected iff the value is
7. For an ideal XOF, the draws are i.i.d., so the rejection count is independent of the accepted values. The
trace leaks a few bits of a function of the secret seed (the same value on every signature), but nothing
about η. Repair: a fixed number of draws, e.g. squeeze a fixed oversized buffer and select in constant
time, or store η in the private key.

## Run it

```
REF="/path/to/Implementations and Test_Vectors/Implementations/Reference_Implementation" ./run_all.sh
# options: KEYS=3000  LEVELS="128 256 384 512"  CC=gcc  SKIP_A=1
```
About 4 minutes on one core. Our log: `results/run_all.log`. REF is never modified or redistributed.
