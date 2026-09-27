# Keyless decapsulation of Polar-KEM

A public-data-only shared-secret recovery against **Polar-KEM** (ICCS NGCC round-1
KEM submission, a "polar-LIP" lattice-isomorphism KEM). From the public key `pk`
and a ciphertext `ct`, the attack recovers the encapsulated shared secret `ss`
**without any part of the secret key**, because the reference decapsulation never
uses the secret except for implicit rejection.

## Why it works (one paragraph)

Polar-KEM claims a lattice-isomorphism trapdoor: `pk = O*B` publishes a basis of a
Construction-D polar lattice rotated by a secret orthonormal isometry `O`, and
decapsulation is supposed to need `O` (equivalently the secret basis) to rotate a
ciphertext back before decoding. In the reference implementation it does not. The
signed permutation that plays the role of `O` is regenerated inside decapsulation
from a **public seed carried in `pk`** (`pk + POLARKEM_PK_SEED_OFFSET`); the secret
`z` is touched only to derive the implicit-rejection key. A ciphertext coefficient
is `sign[i]*(+-q/4) + small_error`, so applying the public permutation and running
the (public) polar successive-cancellation decoder recovers the message `mu`, and
`derive_valid_secret(mu, ct)` returns `ss`. Decapsulation is therefore a public
function of `(pk, ct)`, and IND-CCA security collapses to a one-shot public computation.

## Threat model and purity

IND-CCA / shared-secret recovery. The adversary holds only `pk` and the challenge
`ct`. `src/recover.c` calls exactly two reference routines, `polarkem_recover_message(pk, ct, mu)`
and `polarkem_derive_valid_secret(mu, ct, ss)`, and never reads the secret key: it
is not even loaded. Audit with `grep -n 'sk\|secret\|key' src/recover.c` (no secret-key
read exists).

## Layout

```
src/recover.c   pk+ct -> ss recovery over the submitted KAT vectors (no secret key)
src/tamper.c    correctness / implicit-rejection sanity check (keygen/enc/dec)
Makefile, run_all.sh
```

## Build and run

Point `REFROOT` at the submission package (contains the reference implementation and
the KAT vectors):

```
REFROOT=/path/to/Polar-KEM/Submission_Package ./run_all.sh
```

or build one level directly:

```
make REF=/path/to/Reference_Implementation/PolarKEM-128 recover
./recover /path/to/Test_Vectors/KAT_KEM_PolarKEM-128.txt
```

The reference implementation is NOT bundled.

## Expected output

```
=== PolarKEM-128 ===
KAT_KEM_PolarKEM-128.txt: recovered SS from pk+ct only in 10/10 KAT records
=== PolarKEM-256 ===
KAT_KEM_PolarKEM-256.txt: recovered SS from pk+ct only in 10/10 KAT records
=== PolarKEM-512 ===
KAT_KEM_PolarKEM-512.txt: recovered SS from pk+ct only in 10/10 KAT records
```

## Notes

* Parameters: `N = 512/1024/2048`, `q = 12289/12289/18433`, ternary error. `pk/ct/ss`
  bytes `1024/768/16`, `2048/1280/32`, `4096/2304/64`.
* This is a scheme-level break of the submitted design: the isometry that is supposed
  to be secret is published in `pk`, so no secret is needed to decapsulate. A fix must
  make decapsulation genuinely depend on a secret basis (i.e. actually hide `O`), which
  returns the scheme to the lattice-isomorphism setting it claims and requires the
  LIP hardness to be argued for the concrete polar lattice.
* The reference and optimized implementations share the same public-seed mechanism and
  produce byte-identical KATs, so the attack applies to both.
