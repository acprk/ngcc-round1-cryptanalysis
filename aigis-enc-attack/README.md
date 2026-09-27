# Decryption-oracle attack on Aigis-Enc+

An **implementation-level** IND-CCA break of **Aigis-Enc+** (ICCS NGCC round-1
submission; asymmetric-MLWE KEM with Kyber-family FO/NTT machinery). The
Fujisaki-Okamoto re-encryption check in the reference decapsulation has no
effect on the returned shared secret, so the *unmodified* reference decapsulation
is a **decryption / plaintext-checking oracle**: it returns the real FO key for
every ciphertext, valid or not. This yields a trivial IND-CCA distinguisher,
one-query recovery of the session key of an intercepted ciphertext, and the
plaintext-checking primitive that underlies standard CCA lattice key recovery.

> This is an **implementation** defect, not a break of the Aigis-Enc+ *scheme*.
> The underlying asymmetric-MLWE problem is unaffected (an independent
> lattice-estimator run reproduces the submission's ~2^155/2^292/2^580 core-SVP
> numbers). A one-line patch (write the FO-selected key into `ss`, and fix the
> implicit-rejection seed offset) restores IND-CCA. We do not overclaim.

## Why it works (one paragraph)

`kem.c:mkem_dec` copies the CPA-decryption key into the output `ss` **before**
the re-encryption check runs, and the corrective `cmov` writes into a **dead**
local buffer instead of `ss`:

```c
Hash2(kr, buf, 2*SEED_BYTES);
memcpy(ss, kr, SEED_BYTES);                 /* (1) real key written to ss NOW  */
owcpa_enc(cmp, buf, pk, kr+SEED_BYTES);
fail = verify(ct, cmp, CT_BYTES);           /* (2) FO check computed ...       */
memcpy(buf2, sk-SEED_BYTES, SEED_BYTES);    /* (3) OOB read: should be         */
                                            /*     sk + SK_BYTES - SEED_BYTES  */
memcpy(buf2 + SEED_BYTES, ct, CT_BYTES);
KDF(buf2, SEED_BYTES, buf2, SEED_BYTES + CT_BYTES);
cmov(buf, buf2, SEED_BYTES, fail);          /* (4) ...overwrites buf (DEAD),   */
fail = 0;                                   /*     never ss -> check inert     */
```

Consequently, for **every** ciphertext `ct`,
`Decaps(sk, ct) == Hash2( owcpa_dec(ct) || H(pk) )`, i.e. the FO "real" key with
the implicit-rejection branch never taken. Line (3) additionally reads the
rejection seed out of bounds (`sk - SEED_BYTES`), consistent with the branch
being dead code. All four implementations (Reference, Optimized/avx2,
Additional/neon, Additional/aarch64) share the defect; the specification is
correct.

## Threat model

**IND-CCA.** The adversary has the public key and a decapsulation oracle
(`mkem_dec` with the victim's `sk`); it never reads `sk`. The programs use only
`pk`, chosen/observed ciphertexts, and the oracle. The true secret is read
**only** in blocks marked `[ground truth]`, purely to score results.

* `oracle` measures the oracle itself: honest correctness, tampered-ciphertext
  behaviour, decryption-oracle fidelity `Decaps(ct')==Hash2(Dec(ct')||H(pk))`,
  and plaintext-checking-oracle soundness.
* `recover` mounts the consequences: a legal IND-CCA distinguisher that recovers
  the **session key of an intercepted honest ciphertext in one query** (flip a
  low c1 bit -> `ct' != ct` with the same plaintext), and the sound PC-oracle
  key-mismatch primitive (Ravi et al., TCHES 2020).

## Layout

```
src/oracle.c    decryption / PC-oracle demonstration (C/T/D/P checks)
src/recover.c   IND-CCA distinguisher + 1-query session-key recovery + PC-oracle
Makefile        links the attack against the Aigis-Enc+ reference impl
run_all.sh      reproduces sets I / II / III
```

## Build & run

Point `REF` at an Aigis-Enc+ reference-implementation source directory for the
matching set (must contain `kem.c`, `owcpa.c`, `poly*.c`, `ntt.c`, ...):

```
make PARAMS=1 REF=/path/to/Reference_Implementation/Aigis-Enc+-I
./oracle  300
./recover 300
```

or all three sets at once:

```
REFROOT=/path/to/Reference_Implementation ./run_all.sh
```

The package builds with `-DUSE_SHA3` (the config of the shipped `speed*`
targets); the defect is hash-independent. `fips202x4.c` (AVX keccak, Windows
include path) and `sm3kdf.c` (needs Intel-IPP) are excluded and unused.

## Expected output (per set)

```
=== Aigis-Enc+ set PARAMS=1  (pk=656 sk=1456 ct=896 ss=16) ===
(C) honest correctness      : 300/300 ok
(T) tampered ct             : same_key(BAD)=228  different=72  rc!=0=0  (of 300)
(D) decryption-oracle match : 300/300  Decaps(ct')==Hash2(Dec(ct')||H(pk))
(P) PC-oracle soundness     : 600/600  (correct-accept + wrong-reject)
VERDICT: decryption/PC oracle CONFIRMED (FO check inert) -- IND-CCA broken.
(A) intercepted session-key recovery : 300/300 recovered  (ct' != ct: 300/300, 1 query each)
(B) PC-oracle: correct-accept=300/300  wrong-reject=300/300
```

`rc!=0` is always 0 (decapsulation never rejects). The `(T)` `same_key`/`different`
split reflects whether a *random* single-bit flip happened to change the decoded
message; either way the returned key is the real FO key of the decrypted message
(see `(D)`, which uses guaranteed-invalid ciphertexts and is always 300/300).

## Notes

* Fix for designers: write the FO-selected value into `ss` (e.g.
  `cmov(ss, buf2, SEED_BYTES, fail)`), and read the implicit-rejection seed from
  `sk + SK_BYTES - SEED_BYTES`. With that one-line correction IND-CCA is restored.
* Artifact: https://github.com/acprk/aigis-enc-attack
