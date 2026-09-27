# Coset-encoding malleability of QIMEN-PIKE

A one-query IND-CCA2 break of the reference implementation of **QIMEN-PIKE** (ICCS NGCC
round-1 masked-torsion isogeny KEM), plus a decapsulation denial of service. From an honest
challenge ciphertext an adversary produces a different byte string that the unmodified
reference decapsulation accepts with the identical shared secret, so one decapsulation query
wins the IND-CCA2 game.

## Why it works (one paragraph)

Decapsulation parses the ciphertext into field elements and integer hints, then runs both the
FO re-encryption check and the key derivation on the RE-ENCODED object, not on the received
bytes. The field decoder is non-canonical in two ways: `fp_decode` reads only the significant
bytes of each slot and ignores the trailing padding, and `modimp` silently reduces any encoding
that is at least the prime `p`. So a field element `x` and the element `x+p` (whenever `x+p`
fits the slot), and any padding pattern, decode to the same element. Encoding `x+p` in a slot,
or flipping a padding byte, therefore yields a ciphertext `ct' != ct*` that parses to the same
object and decapsulates to the same key. A companion defect: `ct_decode` reads signed decoding
hints and `ec_..._from_hint` executes `if (hint < 20) x = NQR_TABLE[hint];`, so a negative hint
indexes before the table and segfaults, a remote DoS.

## Threat model and purity

IND-CCA2. The auditor holds a fresh keypair, encapsulates once to get `(ct*, K*)`, and checks
whether a mauled `ct' != ct*` decapsulates to `K*`. `src/malleability_demo.c` calls only the
public KEM API (`kem_keygen`/`kem_enc`/`kem_dec`) and never inspects the secret key beyond
passing it to `kem_dec`; every tampered decapsulation runs in a forked child so a crash is
counted, not fatal.

## Layout

```
src/malleability_demo.c   add-p / padding-flip / hint-crash demo over the reference KEM API
src/cmake_target.txt      the add_executable block to build the demo (appended by build.sh)
build.sh                  copy the reference cmake project, inject the demo, build (Release)
run_all.sh                build + run the demo at NGCC-1/2/3
```

## Build and run

Requires cmake and GMP (as the reference itself does). Point at the reference cmake project
(the directory holding the top-level CMakeLists.txt and src/ngcc/):

```
REF="/path/to/QIMEN-PIKE/Implementations/Implementations" ./run_all.sh
```

`build.sh` copies the reference to a scratch dir, drops in `malleability_demo.c`, appends the
CMake target, and configures with `-DCMAKE_BUILD_TYPE=Release` (the submission's default). The
reference implementation is NOT bundled and is not modified on disk.

## Expected output (unmodified reference, Release build)

```
=== NGCC-1 ===
ALG=NGCC-1 pk=389 ct=602 honest decaps ret=0 match=1
add-p to Fp slot: 8/8 non-canonical ciphertexts accepted with SAME shared secret
  ... offset 515/519/523/527: CRASH signal 11 ...      (negative-hint DoS)
summary: tried=602 same_key_accepted=32 crashed=4 rejected=566
=== NGCC-2 ===
add-p to Fp slot: 8/8 non-canonical ciphertexts accepted with SAME shared secret
=== NGCC-3 ===
add-p to Fp slot: 8/8 non-canonical ciphertexts accepted with SAME shared secret
```

## Notes

* `add-p` malleability is accepted with the identical shared secret at all three levels
  (8/8 each), which is the one-query CCA break. At NGCC-1 the field padding is byte-aligned so
  single padding-byte flips give 32 further equivalent encodings; at NGCC-2/3 the padding is
  sub-byte, so the `add-p` variant is the one used.
* The negative-hint crash (signal 11 in the Release build) is a remote denial of service.
* Implementation-level only; the masked-torsion isogeny hardness is untouched (an independent
  estimate reproduces the submission's levels). Fix: reject non-canonical field encodings
  (value < p, zero padding) and bound-check the hints, or compare/hash the received ct bytes.
