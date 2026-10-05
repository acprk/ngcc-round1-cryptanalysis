# nss-hqc-seedy-width — NSS-HQC: the HQC-384/512 decryption key is determined by a 256-bit sub-seed

**Scope: design (specification Algorithm 1 and the submitted code agree). Category shortfall,
demonstrated.** Affects NSS-HQC-384 and NSS-HQC-512 (claimed classical 384/512, quantum 192/256).
NSS-HQC-128/256 are not affected (they meet their targets exactly). This package backs our Round-1
public comment on NSS-HQC (kem-26).

## What we claim (and verified)

1. **Mechanism (spec).** KeyGen (Algorithm 1, §2.8.1, p. 16) samples `seed_sk ∈ {0,1}^λseed`
   (λseed = 384/512 for these sets, Table 3, p. 25) and then sets
   `(seed_x, seed_y) ← I(seed_sk)` with `I = SHA3-512`, annotated "SHA3-512 splits one 256-bit seed
   into two 256-bit sub-seeds". `y` is sampled from `Expand(seed_y, ·)` only. Decrypt (Algorithm 3,
   p. 19) expands only `y` ("only y is needed for PKE decryption"), and the session key is
   `H_κ(m ‖ ct)`. So the whole decryption capability is a function of the 256-bit `seed_y`, whatever
   λseed is. Table 7 (p. 39) nevertheless lists `T_seed` = 384 / 512 for these sets (eq. (88), §4.4.4).
2. **Mechanism (code).** `nss_hqc_core.c:25` `#define NSS_HQC_I_SEED_BYTES 32u` at all four levels;
   `derive_xy_seeds` (`:432-440`) copies bytes 0-31 and 32-63 of the SHA3-512 digest. Reference and
   Optimized trees are byte-identical. Step [0].
3. **Full size, unmodified code (step [1]).** For each level, a fresh key pair and ciphertext (API DRNG
   seeded from `/dev/urandom`). *Structure check (reads `seed_sk`):* `seed_y` is recomputed, and the
   attacker-side routine rebuilds `y` from those 32 bytes alone, passes the public test
   `wt(s ⊕ h·y) = w_sk`, and decrypts the ciphertext to the encapsulated session key, equal to the
   victim's own `nss_hqc_dec` output. 4/4 levels. False-positive control: 32 random `seed_y` per
   level, 0 pass the public test.
4. **Attack, scale model (step [2]).** In a *copy* of the code, `derive_xy_seeds` keeps only the low
   `BITS` (default 8) bits of `seed_y`; keygen and decapsulation both use it, everything else is the
   submitted code. The attacker gets **only pk and ct**, enumerates `seed_y` over the low `BITS` bits
   with the submitted sampler, keeps the candidate passing the public test, decrypts and derives `ss`.
   HQC-384 and HQC-512: `recovered ss == encaps ss == victim decaps` (YES/YES). The secret key is used
   only for scoring (marked `SCORING`).
5. **Control (step [3]).** The same attacker search against the unmodified code finds nothing in 2^BITS
   trials: the scale-model edit is the only thing that makes the space small.

## Cost at full size

The attack is the step-[2] loop over all 2^256 values of `seed_y`: about 2^255 candidates on average.
Each candidate is one SHAKE256 expansion, fixed-weight sampling and one sparse product `h·y`
(w_sk·n ≈ 2^24.4 bit operations for HQC-384, w_sk = 175, n = 122579; ≈ 2^25.6 for HQC-512,
w_sk = 233, n = 217901), i.e. about **2^279 / 2^281 bit operations**, against claimed 384 / 512.
Grover: about 2^128 oracle calls against the quantum targets 192 / 256. On our host one candidate
costs 0.11 s (HQC-384) / 0.25-0.28 s (HQC-512), single thread, unoptimised. The 2^256 search is
**not** run; the reduction to a 256-bit value is the claim, and the scale model shows the search and
decryption work end to end.

## What we do not claim

- Nothing about the decoding problems (the ISD margins are a separate issue, ngcc.dev kem-26-3).
  Fixing one does not fix the other: kem-26-3 needs larger codes, this needs a wider `I`.
- Nothing about HQC-128/256: 256-bit `seed_y` meets their targets.
- `seed_x` is also 256 bits but is not needed for decryption; it plays no role here.

## Suggested fix

Make `I` output 2·λseed bits (e.g. SHAKE256(seed_sk, 2·λseed/8)) so that `seed_y` has λseed bits, and
size `NSS_HQC_I_SEED_BYTES` per level; or expand `y` directly from `seed_sk` with a domain tag.

## Precedent

Same class as ngcc.dev kem-17-2 (HEP-QC, 256-bit key-generation support, design), kem-21-1 (Viper-384/512
secret restricted to a 256-bit seed), kem-27-1 (NTRE-512 256-bit secret seed) and kem-38-1 (UVW-512).
Here the 256-bit cap is written into the specification itself.

## Run

```bash
REF="/path/to/NSS-HQC/Implementations and Test_Vectors/Implementations/Reference_Implementation" ./run_all.sh
# optional: BITS=10 (scale-model width), K=64 (false-positive control size)
```

Requires gcc (C99/gnu99). Nothing in `$REF` is modified; trees are copied to `./work/`. Output goes to
`out/run.txt`; our run is in `logs/run.txt` (104-core x86_64 host, gcc 9.5.0, ~3 min).

| file | purpose |
|---|---|
| `run_all.sh` | steps [0]-[3] |
| `src/nss_seedy_tool.c` | `full` (structure check + control) and `search` (attack / control) |
| `logs/run.txt` | our run |
