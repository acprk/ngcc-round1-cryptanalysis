# TriQ-KEX / TriQ-KEM: static-key decapsulation timing oracle (same class as the HQC break)

**This is the same class of vulnerability that broke HQC.** TriQ is an HQC-family code-based
KEM. Its FO re-encryption regenerates the encryption randomness with a *rejection sampler whose
iteration count depends on the decrypted message*, so decapsulation time is a plaintext-checking
oracle (PCO) on the secret key. That is exactly the "Don't reject this" hazard of Guo, Hlauschek,
Johansson, Lahr, Nilsson, Schröder (TCHES 2022, [ePrint 2021/1485]), which HQC removed in 2021/2023
by switching to a *rejection-free* sampler. TriQ re-introduces it through a new **bounded-density**
resampling rule. In TriQ-KEX (FSXY two-message AKE) any network party can submit a chosen `CT_A` to
the responder or `CT_B` to the initiator, so the oracle is available on **both long-term keys**.

## Status

- **Timing channel: CONFIRMED (empirically measured, below).**
- **Full key recovery: in progress** — this is a GJS/PCO distance-spectrum recovery of the same
  type as 2021/1485 (HQC-128 there needed ~8.7×10⁵ idealized oracle queries). It is a compute-
  and engineering-heavy follow-up; the structural groundwork is included here and the numbers
  will be updated in this package as the recovery runs. See "Key-recovery groundwork" below.

## The defect (source level)

`crypto_kem_dec` (`src/common/kem.c`) decrypts `m′ = Dec(dk, c)`, derives
`θ′ = G(H(ek)‖m′‖salt)`, then **re-encrypts** with `triq_pke_encrypt(...,θ′)`. That re-encryption
calls the bounded-density sampler `vect_sample_fixed_weight_bd` twice (`src/ref/triq_pke.c:96,98`),
and the sampler has a **data-dependent early `break`** (`src/ref/vector.c:249-254`):

```c
for (iter = 0; iter < N_max; iter++) {
    vect_generate_random_support2(ctx, support, weight);
    if (!vect_check_bounded_density(support, weight, L, gamma)) break;  // count depends on θ′(m′)
}
```

For an adversarial ciphertext `m′` is a function of the secret key, so the number of resampling
iterations — and thus the decapsulation time — leaks a function of the secret. All of this runs
**before** the constant-time implicit-rejection compare (`kem.c:169-174`), so the FO masking does
not hide it.

## Measured evidence (reference impl, TriQ-KEX-128, gcc-11 -O3)

Reproduced on a loaded 104-core host (load avg ~20, powersave). **Pinning to an isolated idle core
is mandatory** — unpinned, the channel is buried under scheduler/frequency-scaling jitter
(sd ≈ 3.7M ticks, not separable); pinned, it is clean:

```
micro:            one extra BD iteration = 15,674 ticks (support_gen 11,486 + bd_check 4,188)
harness_bdtime 4000 31  (min-of-31 full crypto_kem_dec, taskset to isolated core)
  class0 (0 resamples)  n=3683  mean 10,220,477 ticks  sd 113,333
  class1 (1 resample)   n=293   mean 10,257,704 ticks  sd 141,447   Δ = +37,227 ticks (z ≈ 4.4σ)
  class2+ (≥2)          n=24    mean 10,394,078 ticks              +173,601 vs class0 (monotone)
```

- The mean is **monotone in the resample count** (0→1→2+), each extra iteration ≈ +37–80k ticks.
- Rejection frequency ≈ **7.9%** of messages (317/4000).
- A separate quieter-host run measured Δ = +31,725 ticks at 5.6σ and single-shot min-of-31
  separability of 49% TPR @ 1% FPR — enough to instantiate the PCO.

## Key-recovery groundwork (structural, verified against the reference decoder)

TriQ decrypt: `m′ = code_decode( Truncate(v − u·y) )`, `u·y` cyclic mod X^n−1 (n=16301),
`Truncate` keeps coords [0,16128). Secret `y` has weight ω=67. The concatenated decoder:

- RS(42,16) outer code corrects **13 symbol errors**; each symbol is one **384-bit block**.
- Each block = **3 identical copies** of a 128-bit RM(1,7) [128,8,64] codeword; decode sums the
  three copies (majority/repetition vote), so a block flips to a wrong symbol only past a
  per-block radius of ≈ **33 aligned errors (99 raw bit-flips)** — stable across blocks and messages.
- `corrupt_block(v,j)` (99 aligned flips) produces **exactly one** RS symbol error; the RS
  message region is systematic (symbols [26..41]), giving a sharp decode-success step at 13→14
  corrupted message-region blocks. This is the oracle boundary the PCO drives.

The remaining work (in progress) steers `Truncate(u·y)` errors into a chosen block so that a
single support position of `y` tips a boundary-loaded block, turning the decode-success bit into a
per-position test of `y`, then recovers the full support (and `x` from `s = y·h + x`).

## Build and run

```
REF=/path/to/TriQ-KEX/Implementations/Reference_Implementation/TriQ-KEX-128 ./run_all.sh
# pin to an isolated idle core:  CORE=37 REF=... ./run_all.sh
```

The reference implementation is **not bundled**; `src/` here is only our harnesses
(`micro.c`, `harness_bdtime.c`, `exp_oracle.c`) and never modifies the submission.

## Fix

Use a **constant-iteration** bounded-density sampler: always run `N_max` candidates and select
with a mask, or draw a fixed count message-independently, as HQC did after 2021/1485. Applies
verbatim to **TriQ-KEM** (same `vect_sample_fixed_weight_bd` in its own `triq_pke_encrypt`).

[ePrint 2021/1485]: https://eprint.iacr.org/2021/1485
