# trike-review — TRIKE (kem-36): spec, implementation, level and proof issues (forum comment of 2026-10-01)

This is the verification code for our Round-1 comment on **TRIKE** of 2026-10-01. That comment confirms kem-36 and
adds six items plus some minor ones. A later, separate design point (unsalted deterministic FO) is in
[`trike-unsalted-multitarget`](https://github.com/acprk/ngcc-round1-cryptanalysis/tree/trike-unsalted-multitarget/trike-unsalted-multitarget) (separate branch).

No vendor code is included or modified. Point `SUBROOT` at the submission's `Implementations and Test_Vectors`
directory. All C harnesses in `src/` except `scaled3.c` link the submitted sources unmodified. `scaled3.c`
is a standalone re-implementation of the TRIKE-2 bit-flipping decoder, used only for a scaled DFR experiment.

```
SUBROOT=".../Implementations and Test_Vectors" ./run_all.sh            # ~3 min
SUBROOT=... ./run_all.sh long                                           # + item 4 falsification run, ~20 min (2 cores)
SUBROOT=... ./run_all.sh isd                                            # + Tables 9/10 (pip install cryptographic-estimators)
```

`logs/` holds our outputs (gcc 9.5.0, x86-64). Our CPU has AVX-512F but not VPOPCNTDQ/VPCLMULQDQ, so the
optimized tree was built and run on its portable path.

## KATs

The script regenerates both trees for all four sets. All 8 match the submitted `Test_Vectors` byte for byte
(the submitted files use CRLF line endings) (`logs/kat.log`).

## 1. Algorithm 9 (weak-key test) rejects every key as written

The pseudocode accumulates Σµ². The code (`sample.c: weak_key_test`, `weight += i++`, which gives C(i,2)), the App. A
4-cycle formulas and Tables 11–14 all use Σ C(µ,2). The d support positions give C(d,2) intra-block distances, so Σµ = C(d,2) and
Σµ² ≥ C(d,2). This is far above s. Similarly, Σc² ≥ d² is far above s′. `scripts/alg9.py` reads d, s and s′ from
the submitted `trike_params.h`. It also evaluates both readings on 200 random keys per set (`logs/alg9.log`):

| set | C(d,2) | s | d² | s′ | literal Σµ² rejects | binomial rejects |
|---|---|---|---|---|---|---|
| TRIKE-2 | 595 | 46 | 1225 | 83 | 200/200 | 0/200 |
| TRIKE-9 | 6105 | 433 | 12321 | 737 | 200/200 | 0/200 |

TRIKE-5 and TRIKE-7 give the same result. The code's binomial reading is the only self-consistent one, so this has no security impact.

## 2. `kem_dec` leaks `h0` on every decapsulation

In all 8 copies (2 trees × 4 sets), `kem_dec` makes 12 allocations and 11 frees, and `h0` is never freed (`logs/sites.log`).
`src/leak.c` measures `mallinfo2().uordblks` over 200 decapsulations (`logs/leak.log`): TRIKE-2 2064 B/call, TRIKE-5 8209,
TRIKE-7 16400, TRIKE-9 16400; the optimized tree (TRIKE-2/9) gives the same. Encapsulation shows no growth. ASan reports
`Direct leak … kem_dec KEM_AlgorithmInstance.c:306` (`logs/asan.log`). At 1000 decapsulations/s this is about 59 GB/hour for TRIKE-7/9.
The fix is `free(h0)` after `free(t0)`.

## 3. TRIKE-9's label exceeds the DRNG state

Every `ICCS/drng.h` has `SEEDLEN (55)`, i.e. a 440-bit SM3-DRNG state that carries all secret randomness. This gives
2^440 < 2^512 classical and 2^220 < 2^256 under Grover (`logs/drng.log`). It is a limit of the ICCS DRNG; with
an ideal generator it disappears.

## 4. δ-correctness omits the boundary weak-key classes (argument gap, not an attack)

App. A analyses only the fully filtered m0. The boundary class m0−1 rests on 10^7 (10^6 for TRIKE-7/9) zero-failure runs,
which give DFR ≤ 2^-21.67 (2^-18.35). Since DFR_avg ≥ Pr[boundary]·DFR(boundary), `scripts/wk2.py` uses the
spec's own τ formulas to obtain (`logs/wk2.log`):

| set | worst boundary density | × measured bound | claimed | shortfall |
|---|---|---|---|---|
| TRIKE-2 | 2^-25.00 | 2^-46.67 | 2^-128 | 81 bits |
| TRIKE-9 | 2^-96.93 | 2^-115.28 | 2^-512 | 397 bits |

Before concluding, we tried to falsify the point (`run_all.sh long`, `src/scaled3.c`, r = 12500). We implanted f = 6 arithmetic
structure and passed the keys through a faithful port of the weak-key filter. The DFR was 1.700e-2 against 1.753e-2 for
random keys (60000 trials each, z = −0.71), so there is no elevation. 47% of the implanted keys were rejected by the filter
(`logs/wk_*.out`, plus a 200000-trial pair at r = 12750). This is an incomplete argument, not evidence of a higher DFR.

## 5. Theorem 4's reduction is not implementable (proof defect)

The proof lets B′ test weakness on pk = (h0, h1, h2), but the public key is (σ, r2). Deciding weakness from the public
key is no easier than key recovery. A correct black-box argument conditions on the rejection event and loses an additive
ρ/2. Here ρ is the rejection rate, 0.19% in Table 11 for TRIKE-2, and `src/rej.c` measures 0.155% with the shipped
thresholds at full parameters (`logs/rej.log`). The loss is therefore about 2^-10, not the claimed 0.0043 bits.

## 6. Side channels (source level; cache attack PLAUSIBLE, not demonstrated)

Reference `calc_upc_block` reads `s[idx_to >> 3]` with `idx_to = (i + idx[k]) % r`. Optimized `gf2x_shift` loads
`in_64 + (shift >> 6)` with `shift = idx[k]`. In both, the load address is a secret support position, touched
3·d·7 = 735 times per decapsulation for TRIKE-2. The reference `compare_vec` is `-(memcmp(...) != 0)`, which is
variable-time, although §2.3 says the reference implementation is constant-time (`logs/sidechannel.log`).

## Minor

- `drng_algorithm` is a global that the library never seeds. `src/rng.c` leaves it unseeded and gets the identical
  pk in 3 independent processes (`logs/rng.log`).
- Three entries in Tables 12/14 disagree with the spec's own formulas. They should be 2^-125.97, 2^-107.12 and
  2^-180.29; the printed values are all larger, i.e. conservative (`logs/wk2.log`, "SPEC MISMATCH").
- Table 8 prints TRIKE-2 r = 15541 (Table 1 and the code use 15581). §1.5 says "five parameter sets" and lists six.

## Tables 9/10

`scripts/est2.py` reproduces every Prange/Stern entry exactly and the BJMM entries within 0.75 bit (`logs/est2.txt`).
After the DOOM discount, TRIKE-2 key recovery is 171.78 (spec 171.78) and message recovery 168.23 (spec 167.86;
our comment quoted the spec's value). Hardness has ample margin. `scripts/bias.py` also bounds the samplers'
modular bias (worst case 2^-6.43, TRIKE-9 error sampler).
