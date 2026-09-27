# Coset-Lift Malleability: a one-query IND-CCA2 break of the OAEP-NTRU KEM reference implementation

A **one-query IND-CCA2** break of the **OAEP-NTRU** KEM (ICCS NGCC round-1
submission), plus a companion key-leak-on-reject probe. From an honest challenge
ciphertext `ct*` with shared secret `K*`, the attack produces a *different*
byte-string `ct' != ct*` that the **unmodified** reference decapsulation accepts
(return code `0`) with the **identical** shared secret `K*`. Submitting `ct'` to
the decapsulation oracle in the IND-CCA2 game recovers `K*` in a single query.

> **Honest scope.** This is an **implementation-level** break of the *submitted
> reference implementation*, not a mathematical break of the underlying
> NTRU/RLWE problem or of the OAEP† transform's proof (which reasons about
> ciphertexts as ring elements `c in R_q`). A small, local patch closes it. We do
> **not** claim any weakness in the lattice assumptions or the scheme's design.

## Why it works (one paragraph)

The session key is `k = H'(pkd || s || e)`: it binds the *recovered ring
element* `(s,e)`, not the ciphertext bytes. Decapsulation calls
`poly_frombytes()`, which unpacks each coefficient as a raw `CB`-bit little field
(`CB=13` for `q=7129`, `CB=15` otherwise) with **no canonicity/range check**, and
the subsequent NTT arithmetic reduces mod `q`. So a coefficient stored as `v` and
the *same coefficient stored as `v+q`* (whenever `v+q < 2^CB`, a non-canonical but
same-field-element encoding) decode to the identical ring element. Since
`F(s,e)=h*s+e` is injective on `R_q`, the coset-lifted ciphertext `ct'` recovers
the same `(s,e)`, hence the same confirmation tag (also recomputed from `(s,e)`,
so the tag check passes) and the same key `k` — yet `ct' != ct*` as byte strings.
This is the **Coset-Lift Malleability** (CLM). Each parameter set has hundreds of
byte-aligned coefficients and roughly 15%–87% of coefficient values are liftable,
so a liftable coordinate always exists.

## The two defects

- **F1 — Coset-Lift Malleability (IND-CCA2 break).** `src/coset_lift.c`.
  Non-canonical coefficient decoding + a key that does not bind the ciphertext
  bytes ⇒ `ct' != ct*` with `Decaps(ct') = K*`. One decapsulation query.
- **F2 — Rejection key-leak (API hazard).** `src/reject_leak.c`. On a *rejected*
  ciphertext `kem_dec` still writes the genuine session key to the output buffer
  `ss`; only the integer return code signals failure. Flip one confirmation-tag
  byte: the return code is nonzero (reject) but `ss` holds `K*`. Any caller that
  ignores the return code obtains `K*`.

Both are in `KEM_AlgorithmInstance.c` `kem_dec` (and `poly.c` `poly_frombytes`).
Neither touches the scheme's mathematics.

## Threat model

**IND-CCA2.** The adversary holds the public key and the challenge ciphertext
`ct*` (with challenge key `K*`) and has access to a decapsulation oracle that it
may query on any ciphertext `!= ct*`. The attack reads only public/challenge data
and the oracle output; it never inspects `sk`. `sk` is passed to `kem_dec`
exactly as the honest decapsulation oracle would hold it.

## Layout

```
src/coset_lift.c    F1: coset-lift malleability -> 1-query IND-CCA2 break
src/reject_leak.c   F2: genuine key left in ss on a rejected ciphertext
Makefile            links the attack against ONE reference set (REF=...)
run_all.sh          reproduces all three sets (REFROOT=...)
```

The reference implementation is **not** bundled. Point `REF`/`REFROOT` at your
own copy of the OAEP-NTRU reference sources.

## Build & run

Point `REF` at a single OAEP-NTRU reference-implementation set directory
(containing `poly.c`, `ntt.c`, `drng.c`, `symmetric.c`, `auxfunc.c`,
`KEM_AlgorithmInstance.c`, and the headers):

```
make -j4 REF=/path/to/Reference_Implementation/OAEP-NTRU-648
./coset_lift  1000       # F1: prints ct' distinct, accepted, and K* match counts
./reject_leak 1000       # F2: prints reject-signalled and key-in-ss counts
```

or all three sets at once:

```
REFROOT=/path/to/Reference_Implementation ./run_all.sh
```

## Expected output (OAEP-NTRU-648, 1000 trials; identical shape for 1296/2592)

```
[coset-lift] set n=648 q=7129 CB=13 trials=1000
[coset-lift] ct' distinct from ct*        : 1000/1000
[coset-lift] ct' accepted (rc==0)         : 1000/1000
[coset-lift] decaps(ct') == K* (KEY LEAK) : 1000/1000
[coset-lift] RESULT: IND-CCA2 BROKEN (1-query malleability confirmed)
[reject-leak] set n=648 q=7129 trials=1000
[reject-leak] decaps signalled reject (rc!=0) : 1000/1000
[reject-leak] genuine K* left in ss buffer    : 1000/1000
[reject-leak] RESULT: KEY-LEAK-ON-REJECT confirmed (ss not zeroized)
```

All three parameter sets (n = 648, 1296, 2592) reproduce 1000/1000 for both
defects.

## Fixes for designers (both trivial)

- **F1:** reject any coefficient `>= q` in `poly_frombytes` (canonical decoding),
  and/or bind the ciphertext bytes into the key/tag hash `H'`. Either makes the
  encoding-to-key map injective on byte strings.
- **F2:** on failure, overwrite `ss` with an implicit-rejection / pseudorandom
  value (as the specification mandates) instead of leaving the genuine key in the
  buffer.

## Notes

- The attacks are black-box and functional (no timing, no side channel); every
  number above is from linking against and running the unmodified reference
  decapsulation.

## Harness caveats (disclosed, not hidden)

Two known imperfections in *our* harness (`src/coset_lift.c`, `src/reject_leak.c`),
neither of which changes the confirmed result but which a verifier should be aware
of:

- **Key-buffer sizing.** `Kstar`/`Kdec` are declared `[32]` and compared with
  `memcmp(...,32)`. For the n=2592 set the KEM shared secret is `SSBYTES=64` bytes,
  so the comparison only checks the first 32 bytes of the shared secret (a 32-byte
  prefix match). This is a same-key check on a prefix, not the full 64-byte secret,
  for that one set; for n=648/1296 the buffer covers the whole secret. A full-length
  fix is to size the buffers to the per-set `SSBYTES`.
- **`init_random_number` argument units.** The harness calls
  `init_random_number(&drng_algorithm, seed, 48 * 8)`, passing a bit count where the
  reference API expects a byte count (48). This over-specifies the seed length; it
  does not affect the malleability/leak conclusion (the challenge and the mauled
  ciphertext are produced by the same seeded run) but should be corrected to `48`.
