# NIIKE: no public-key validation, and a non-functional NGCC-III

Verification package for a public comment on **NIIKE** (ICCS NGCC round-1,
isogeny-based non-interactive key exchange). We did **not** break the underlying
Houben / Wang-Lai-Lin-Zhao group action. The findings are about the submission as
delivered. Every number here comes from building and running the vendor reference
implementation; the comment text is in [`docs/comment.txt`](docs/comment.txt).

## Findings backed by this package

1. **No public-key validation (demonstrated active break).** `decode_bundlevertex`
   returns `void` and discards the `fp_decode` canonicality flag at all 15 call
   sites; `kex_derive_ss_a/b` then `return 0` unconditionally. An all-zero,
   non-canonical, or random peer public key is accepted (rc = 0) and the derived
   shared secret is `00…0`, **independent of the victim's long-term secret key**
   (lv128 and lv256). An active peer who chooses the public key learns the shared
   secret. Oriented-key validation is an open problem by the construction's own
   author (Houben, ePrint 2025/1098 §7).
2. **NGCC-III is non-functional / its KATs are not genuine.** The lv512 secret key
   is hard-coded (`make_SecretKey` copies fixed `temp1`/`temp2`, RNG commented
   out) — in the shipped KAT, `Seed` is 10/10 distinct but `SKa/SKb/PKa/PKb/SS`
   are 1/10. And `assert(top == 0)` in `bundleeval_action_stra` fires with
   `top == 1` when `M_LEN == 0` (lv512), aborting in the default (asserts-on)
   build, so lv512 cannot produce a key at all.
3. **Inconsistent NGCC-III prime.** Code prime 16394-bit (7 mod 8) ≠ spec §5.5
   prime 16392-bit (3 mod 8, which violates the spec's own §5.3 `p ≡ 7 mod 8`
   rule); the KAT field length (2049 B) matches the spec prime, not the code.
   lv128/lv256 KATs reproduce byte-for-byte — NGCC-III is the sole exception.
6. **NGCC-I misses the spec's own Table 9.1** (`|Disc| = 2^4046 < 2^4096`,
   `log2 p = 254.4 < 256`), and NGCC-III is the CSIDH setting (σ = π−1 ⇒
   Disc = −4p), where the "large discriminant" innovation is unused.

(Numbering follows `docs/comment.txt`; items 4, 5, 7 there are spec/proof/build
observations not needing this harness.)

## Threat model and purity

Active NIKE with static keys. `src/probe.c` holds a victim keypair only to call
the reference `kex_derive_ss_a` on an attacker-chosen peer public key; it never
inspects the secret. No reference source is modified. The probe links the vendor
reference object files unchanged (excluding `KAT_KEX.c.o`, which carries the
reference `main`). The verifier reads only public artifacts: the reference source
constants (prime limbs, torsion lists, sizes) and the public KAT vectors.

## Layout

```
verify_niike.py    parameter arithmetic + KAT statistics (reads REFROOT / KATROOT)
src/probe.c        public-key-validation attack probe (links the reference objects)
run_all.sh         cmake-builds the vendor tree read-only, runs verifier + probe
docs/comment.txt   the public comment
logs/run_all.log   a captured run
```

## Build and run

The reference implementation is **not** bundled. Point `REFROOT` at your copy:

```
REFROOT="/path/to/NIIKE/Implementations and Test_Vectors/Implementations/Reference_Implementation" \
  ./run_all.sh
```

`REFROOT` must contain `NIIKE-lv128`, `-lv256`, `-lv512` and the shared
`protocols/`, `ec/`, `gf/`, `common/`, `ngccapi/` directories. `KATROOT` defaults
to `$REFROOT/../../Test_Vectors`. Requires `cmake`, a C compiler (`CC`, default
`gcc`), and `python3`. The probe is built at `-O2 -DNDEBUG` (Release = the
configuration a deployer ships; in the default `-O0` build a byte-flipped key
instead trips a debug-only assert — see comment item 5).

## Expected output (abridged)

```
(1) all-zero peer pk           rc=0  ss_allzero=1
(2) all-0xFF (non-canonical)   rc=0  ss_allzero=1
(3) pseudo-random peer pk      rc=0  ss_allzero=1
(5) 2nd victim + all-zero peer  ss_allzero=1  (== independent of victim secret)
RESULT: ... CONFIRMED

lv512: SKa 1/10 distinct <== 1 value for all rows (hard-coded key!)
       KAT PK => FP2 = 4098 B ...; code FP2 = 4100 B, PUBLICKEY_BYTES = 41000
```
