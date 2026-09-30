# rudraksh2-symmetric-cap — Rudraksh2 (kem-34): a 256-bit symmetric cap on the 512 sets, and a broken Cortex-M4 constant

Verification code for our Round-1 public comment on **Rudraksh2**. As of 2026-09-30 ngcc.dev
records *no published vulnerability finding* for kem-34 and the forum thread has no replies, so
both findings below appear to be new; the constant-time review (kem-34) inspected only the public
matrix rejection sampler and explicitly left "lower-level decoding, sampling and compiler output"
open.

Everything here reads only public data or is used only to *check* a reconstruction against a
genuine key/session. **No vendor source or binary is redistributed** — point `REF=` at the
submission's `Implementations/` directory.

## Findings

### 1 — The 512-level secret key and session key are functions of a single 256-bit SM3 chaining value (severity A: below claimed category, demonstrated)

Rudraksh2 instantiates its XOF/PRF/hashes as a counter-mode wrapper around **SM3** (spec §2.6.2),
whose chaining value is **256 bits** wide. On the 512 sets `lenK = KEM_SYMBYTES = 64` bytes, which
is *exactly one SM3 message block*, so:

- **Secret key.** `indcpa_keypair` draws `noiseseed` (64 B) and computes
  `s,e ← CBD(pseudoXOF(noiseseed‖i))`, `pseudoXOF(x)=SM3(x‖ctr₁)‖SM3(x‖ctr₂)‖…`. Every one of those
  SM3 calls shares the first-block chaining value `CV = CF(IV, noiseseed)` (256 bits); everything
  after the first block (`i`, the counter, padding, length) is a public constant. Hence the entire
  secret key is a deterministic function of the 256-bit `CV`.
- **Session key.** In `kem_enc`, `buf = m(64 B)‖H(pk)(64 B)` and `K,seed_r = hash_g(buf)`; `m` is
  the first block, so `K = F(CF(IV,m), H(pk))`.

`src/cap512.c` runs the **unmodified** `kem_keygen`/`kem_enc`, then rebuilds (a) the secret-key
bytes from the 32-byte `CV` of `noiseseed` and (b) the session key `K` from the 32-byte `CV` of
`m`, using nothing else:

```
Rudraksh2-512 secret key rebuilt from 256-bit SM3 chaining value: 50/50 exact
Rudraksh2-512 session key  rebuilt from 256-bit SM3 chaining value: 50/50 exact
```

**Consequence.** An attacker enumerates `CV ∈ {0,1}²⁵⁶` (for the key: for each candidate compute
`s`, test whether `b − A·s` is short; for the session key: recompute `seed_r`, re-encrypt, compare
to `ct`). This is ≈ `2²⁵⁶` classical / ≈ `2¹²⁸` under Grover, against the **claimed classical 512 /
quantum 256** for `Rudraksh2-512-I` and `-512-II` — short by 256 bits classically and 128 bits
quantumly. The spec never analyses the symmetric strength of the 512 sets. This is the same class as
ngcc.dev kem-11 / kem-21 / kem-27 / kem-38 and COMPASS problem 1, none of which is currently listed
for Rudraksh2.

**The seed/message size is the real ceiling for every set** (`src/keycap.c`, step [1a]). Because
`K = G(m ‖ H(pk))` is a function of the `lenK`-byte message and the public key alone — we rebuild it
from `m + pk`, no `sk` and no `ct`, 100/100 at each level — generic Grover message search costs
about `2^(4·lenK)`:

| set | lenK | classical (min lattice, seed) | quantum (min QSVP, seed-Grover) | claimed cl / qu | verdict |
|---|---|---|---|---|---|
| 128-I | 16 B | 2¹²⁸ (msg 2¹²⁸, CSVP 2¹²⁹) | **2⁶⁴** (msg-Grover) | 128 / 80 | classical OK; **quantum 2⁶⁴ < 80** † |
| 256-I | 32 B | 2²⁵⁶ | 2¹²⁸ | 256 / 128 | meets exactly (no margin) |
| 512-I/II | 64 B | **2²⁵⁶** (SM3 cap) | **2¹²⁸** (SM3 cap) | 512 / 256 | **short by 256 / 128 bits** |

† The 128 sets' quantum figure of 80 is not backed by a 128-bit message: plain Grover message
search is `2⁶⁴`. This is the AES-128 situation and its status depends on the MAXDEPTH model, so we
flag it rather than call it a clean break. The **unambiguous** shortfall is the 512 set, where the
256-bit SM3 chaining value caps both the classical (`2²⁵⁶` vs 512) and the quantum (`2¹²⁸` vs 256).

*Not claimed:* we do not run the `2²⁵⁶`/`2¹²⁸` search. The demonstration is the exact reduction of
the key/session to a 256-bit value, plus the message→key reconstruction that fixes the ceiling.

### 2 — Cortex-M4 128/256 use a different error-correction constant, so they do not interoperate with the reference (severity B: implementation)

`Additional_Implementations/Cortex_M4/lwekem{128,256}/crypto_kem/Rudraksh2/Rudraksh2/minal.c:15`
sets `#define MINAL_BETA 0`. The spec (Table 1, `(B,β)=(2,220)`), the reference implementation, the
AVX2 implementation and **Cortex-M4-512** all use 220 (M4-512 uses 510, also correct). β enters the
2-D B2-Minal code that maps message bits to coefficients, so the M4 128/256 decapsulator computes a
different message from the same ciphertext.

```
KAT vs submitted Test_Vectors:      m4-128 MISMATCH   m4-256 MISMATCH   (ref/opt/m4-512 all MATCH)
interop (200 sessions, both ways):  enc=m4 dec=ref 0/200   enc=ref dec=m4 0/200   (ref↔opt 200/200)
one-line fix (β→220):               m4fix-{128,256} KAT MATCH; enc=m4fix dec=ref 200/200 both ways
```

Every honest M4↔reference session silently falls through to implicit rejection (both parties derive
different keys). By the vendor's own shipped DFR table the β=0 code also has a worse decryption-
failure rate — `128-I: 2⁻⁹⁴·⁵` (claimed `≤2⁻¹⁰⁰`), `256-I: 2⁻¹⁵⁰·⁶` (claimed `2⁻¹⁶¹`) — still far
from exploitable, so this is an interoperability/correctness bug, not a break. Fix in
`patches/m4-minal-beta.patch`.

### 3 — (`--latt`, minor) The Rudraksh2-II sets are weaker than ML-KEM-512 in every model, and ship no implementation

`latt/latt_II.py` (lattice-estimator, exact CBD, `l·n` samples), with an ML-KEM-512 (NIST L1)
anchor from the same script:

| set | usvp MATZOV | usvp CoreSVP | dual_hybrid MATZOV | dual_hybrid CoreSVP |
|---|---|---|---|---|
| ML-KEM-512 anchor | 143.8 | 118.6 | 139.7 | 115.5 |
| Rudraksh2-128-II | 139.3 | **113.6** | 133.3 | **109.3** |
| Rudraksh2-256-II | 281.4 | 261.6 | 265.3 | 245.2 |

`128-II` is 4.5–6.4 bits below the L1 anchor in every model (the authors' own Table 14 CSVP is
`2¹¹⁴`); none of the `-II` sets ships an implementation.

## How to run

```
REF=/path/to/Rudraksh2/Implementations ./run_all.sh          # findings 1 & 2, ~1 min
REF=/path/to/Rudraksh2/Implementations ./run_all.sh --latt   # + finding 3 (needs sage + lattice-estimator; ~15 min)
```

- `REF` is the submission's `Implementations/` directory (contains `Reference_Implementation/`,
  `Optimized_Implementation/`, `Additional_Implementations/Cortex_M4/`, `Test_Vectors/`). Both the
  submission package and the vendor's own tree with the same layout work.
- `$REF` is **never modified**: each set is copied to `./work/<impl>-<L>` and the one-line M4 fix is
  applied there. Set `CC=gcc-11` if your default gcc is newer than the vendor's build.
- `LATTICE_ESTIMATOR=/path/to/lattice-estimator` for `--latt` (default `/home/luck/xzy/lattice-estimator`).
- `logs/` holds our own run outputs; `out/` is overwritten by your run.

## What each program does

| file | finding | reads secret? |
|---|---|---|
| `src/keycap.c` | 1 (ceiling) | no (K rebuilt from m + pk only; no sk, no ct) |
| `src/cap512.c` | 1 (512 cap) | only to *check* the rebuilt sk/K byte-for-byte (marked in-source) |
| `src/cross.c`  | 2 | no (decaps needs `sk`, but the finding is the ss (dis)agreement, not `sk`) |
| `latt/latt_II.py` | 3 | no (parameters only) |

The 512-level cap program `#include`s the vendor `auxfunc.c` so it can reach SM3's (static)
compression function; it links against the vendor's public API for everything else. All numbers
above come from running this package against the named vendor tree.

This analysis was prepared with AI assistance (Anthropic Claude); every number comes from the code
here run against the vendor implementation.
