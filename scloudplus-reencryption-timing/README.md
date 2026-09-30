# Scloud+ decapsulation: the re-encryption rejection sampler leaks the decrypted message through timing

A constant-time / timing finding against **Scloud+** (ICCS NGCC round-1 unstructured-LWE KEM,
`kem-35`). During FO re-encryption, decapsulation re-samples the secret/error from the decrypted
message `m'` using a **rejection sampler** whose number of XOF squeezes is **data-dependent**. The
squeeze count is a deterministic function of `m'` (`seed = F(G(m' || H(pk)))`), so **decapsulation
time depends on the decrypted message** — a plaintext-dependent timing channel in the unmodified
optimized build, the same mechanism as the accepted `kem-30-1` (PolarLAC). The rest of
decapsulation, including the Barnes–Wall decoder, is constant-time.

This is **Medium**: measured and repeatable, secret-derived, with a null public-value control, but
coarse (no stable single-query oracle; ~10^3 decaps per oracle bit on our host) and **no key
recovery was attempted**, consistent with the bar set by `kem-30-1`.

## Root cause (source)

`scloud_kemdecaps` (`common/kem.c`) re-encrypts `m'`: `rk = G(m' || H(pk))`, `seed = F(rk)`,
`r1,r2 = seed`, then `sample_sp(r1)` / `sample_e12(r2)`. For the BD6 (L256/L384) and BD12 (L512)
sets these run a rejection sampler (`common/sample.c`):

```
static void sample_bd6_refill(sample_reject_reader *reader) {
    do {
        const uint8_t *bytes = reader_bytes(&reader->reader, SAMPLE_BD6_BATCH_BYTES, tmp);
        reader->bit_len = scloudplus_sample_bd6_bits_backend(bytes, ...);  // # accepted, DATA-DEPENDENT
        reader->bit_pos = 0U;
    } while (reader->bit_len == 0U);
}
static inline uint8_t sample_bd6_next_bit(sample_reject_reader *reader) {
    if (reader->bit_pos == reader->bit_len) sample_bd6_refill(reader);   // refill when queue empty
    return reader->bits[reader->bit_pos++];
}
```

Each 3-bit candidate is accepted iff `candidate < 6` (BD6) / `< 12` (BD12), so the number of accepted
bits per batch — hence the number of refill iterations, hence the number of 4-block SHAKE256 (or SM3)
squeezes in `reader_refill` — depends on the XOF stream, which is seeded from `m'`. (The accepted-bit
compaction `bits[count] = …` is also a store at a secret-dependent index; same root cause.) The AVX2
backend is no different: `scloudplus_sample_bd6_bits_backend` returns a data-dependent `count`.
L128 (BD4/BD2) and L192 (BD2) have no rejection loop and are invariant.

## What this package shows (`run_all.sh`, ~2 min at L256)

1. **Deterministic (host-noise-free):** 5000 honest decapsulations, counting the XOF squeezes the
   re-encryption sampler performs. The count is message-dependent:
   - **L256 (BD6):** 296–301 batches, **53–54** XOF squeezes;
   - **L512 (BD12):** 800–807 batches, **189–191** squeezes;
   - L128/L192: constant (no rejection loop).
2. **Timing (sampler microbench = exactly what `pke_enc` runs, less noise than full decaps):**
   seeds binned by squeeze class and timed (500 reps, shuffled, core-pinned). Crossing an XOF-squeeze
   boundary costs about **+4.6k cycles** and each extra batch about **+0.8–1.0k** (per-batch estimated
   *within* one squeeze class, then per-squeeze backed out — the two are collinear across adjacent
   classes, so a naive 2-variable OLS does not identify them). The adjacent squeeze-class gap we
   measure is **~6k cycles (Welch t ≈ 55)**, which is *one squeeze plus ~1.6 extra batches*, not the
   per-squeeze cost; its absolute magnitude is host-load dependent. The public-value control is null.
3. **Corroboration:** the Barnes–Wall decoder object (`encode.o`) has **div=0, cmov=0, setcc=0** at
   every level and compiler — the decoder and the rest of decapsulation are constant-time; only the
   re-encryption sampler leaks.

Full end-to-end measurements on the unmodified `kem_dec` (L256 AES/SHAKE, L384, L512; LO-vs-HI class
gaps ~7–14k cycles; 0% per-ciphertext classification error at L256 with enough repetitions; kem-30-1
comparison) are in our review notes; this package ships the deterministic core and the sampler
microbench, which are the load-independent evidence.

## Run it

```
REF="/path/to/Scloud+/Implementations and Test_Vectors/Implementations" ./run_all.sh
# options: L=256|384|512 (BD-rejection sets), FAM=AES|SHAKE|SM3, CC=gcc-11
```

`REF` is the vendor `Implementations/` directory. It is **not** redistributed here and is never
modified in place: `run_all.sh` copies `common/sample.c` into `build/` and applies a **5-line counter
patch** (`patches/count.patch`); every other vendor file is compiled from `REF` unchanged. The timed
binary links the **unmodified** `common/sample.c`.

## Layout

```
patches/count.patch   5-line instrumentation (global counters at the refill / straddle points)
src/gen_count.c       honest keygen/encaps/decaps loop; records XOF squeezes per decaps (public API only)
src/sampler_bench.c   times sample_sp+sample_e12 (what pke_enc runs) on seeds binned by squeeze class
src/analyze.py        count distribution; per-seed-median timing by class + Welch t
run_all.sh            builds against REF, runs [1] counts [2] timing [3] decoder div/cmov check
```

## Two further observations (own subdirectories, run separately)

- `dfr/dfr_model.py` (self-contained pure Python; no vendor code): the spec Sec. 3.1.4 / Table 16
  DFR is **not a ball-failure upper bound**. It reproduces Table 16 under the spec's Gaussian marginal
  (A column = -138.5/-220.9/-271.8/-457.7/-552.6) and shows the exact coordinate marginal (B) and the
  key-conditional model (C) are heavier — up to **+34 bits at L512** — so the margin over 2^-512
  collapses to single digits. A proof gap, not a demonstrated failure (the ball bound is very
  pessimistic for this decoder). See `dfr/README.md`.
- `estimator/weak_key_scan.py` (needs Sage + lattice-estimator via `ESTIMATOR=`): a cost/advantage
  (T/eps) adversary against the i.i.d. BD(1/12) L512 secret reaches **2^487.6-490.8 (CoreSVP)**, about
  21-24 bits below 512 — metric-dependent (the primal hybrid stays at 2^555.8) and not practical
  (still 2^488); L128-384 unaffected. See `estimator/README.md`.

## Severity and fix

**Medium**, `kem-30-1` (PolarLAC) analogue. Measured, repeatable, secret-derived; coarser than
PolarLAC (adjacent classes differ by ~0.8k cycles / one batch; crossing an XOF-squeeze boundary is
~4–6k), so a plaintext-checking oracle would use the rare low-squeeze class and pay ~10^3 decaps per
bit. No key recovery attempted.

Fix (local to `common/sample.c` / `avx2/sample_avx2.c`): make the number of batches and XOF squeezes
data-independent — process a fixed upper-bound number of batches (failure probability < 2^-128 for the
fixed coefficient count) with constant-time compaction, or replace the rejection sampler with a
non-rejection construction (fixed-point comparison against 1/6, 1/12). The same change removes the
secret-indexed `bits[count]` store and the analogous one-shot leak in keygen's `sample_s`.
