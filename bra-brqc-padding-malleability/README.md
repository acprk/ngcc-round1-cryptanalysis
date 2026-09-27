# Padding-bit malleability of BRA and BRQC

A one-query IND-CCA2 break of the reference implementations of **BRA** ("Blockwise RQC
with Augmented Gabidulin codes") and **BRQC** (ICCS NGCC round-1 rank-metric code KEMs
from the same team). From an honest challenge ciphertext, an adversary flips unused
ciphertext-encoding padding bits to obtain a *different* byte string that the unmodified
reference decapsulation accepts with the **identical** shared secret. Submitting it to the
decapsulation oracle wins the IND-CCA2 game in one query, and it also breaks
ciphertext-binding (MAL-BIND-K-CT).

## Why it works (one paragraph)

`rbc_vec_to_string` / `rbc_vec_from_string` pack `n` elements of `F_{2^m}` into
`ceil(n*m/8)` bytes; for every parameter set `n*m` is not a multiple of 8, so the last byte
of `u` and of `v` each carry unused padding bits that the parser silently discards. Two
things then conspire in `bra_decaps` / `brqc_decaps`: (1) the FO check compares
`rbc_qre_to_string(u)`, the *re-serialised* canonical bytes of the parsed `u`, against the
re-encryption, not the received ciphertext bytes; and (2) the shared secret
`K = H(pk || m || to_string(u) || to_string(v) || salt)` also hashes the re-serialised
objects. The received ciphertext bytes are therefore never bound, so flipping any subset of
the padding bits yields a distinct byte string that decapsulates to exactly the challenge
key. This is an implementation defect: the rank-code (DIBRSD) hardness is untouched, and a
one-line fix (compare or hash the received bytes, or reject non-zero padding) closes it.

## Equivalent encodings per ciphertext

| scheme | padding bits (last byte of u, of v) | same-key single-bit flips | equivalent encodings |
|---|---|---|---|
| BRA-128 / 256 / 512 | 5 + 5 | 10 | 2^10 |
| BRQC-128 | 7 + 7 | 14 | 2^14 |
| BRQC-256 | 5 + 5 | 10 | 2^10 |
| BRQC-512 | 1 + 1 | 2 | 2^2 |

`C-Multi-UR-AG`, a third submission from the same team, shares the same RBC library and the
same defect.

## Threat model and purity

IND-CCA2. The auditor holds a fresh keypair, encapsulates once to get `(ct*, K*)`, and asks
whether a mauled `ct' != ct*` decapsulates to `K*`. `src/kem_audit.c` calls only the public
NGCC KEM API (`kem_keygen` / `kem_enc` / `kem_dec`) and never inspects the secret key beyond
passing it to the reference `kem_dec`; every tampered decapsulation runs in a forked child so
a crash is counted, not fatal.

## Layout

```
src/kem_audit.c   generic NGCC-KEM audit: roundtrip, exhaustive single-bit ct malleability
                  scan (same-key?), wrong-sk decaps, random-ct decaps
build.sh          copy a reference level, build it, link the audit tool
run_all.sh        audit BRA-128/256/512 and BRQC-128/256/512
```

## Build and run

```
REFROOT_BRA=/path/to/BRA/Implementations/Reference_Implementation \
REFROOT_BRQC=/path/to/BRQC/Implementations/Reference_Implementation ./run_all.sh
```

or one level:

```
./build.sh /path/to/Reference_Implementation/BRA-128 KEM_BRA-128.h
./audit 5 -1 30        # 5 roundtrips, full single-bit scan, 30 random-ct trials
./audit 5 0 0 1013,2027   # fast: scan only the two padding bytes of BRA-128
```

The reference implementations are NOT bundled; `build.sh` copies each to a scratch dir and
never edits the reference on disk.

## Expected output

```
BRA-128 :  bitflip scan: tried=16736 same_key=10 nonzero_ret=0 crashes=0
BRA-256 :  bitflip scan: tried=27248 same_key=10 nonzero_ret=0 crashes=0
BRA-512 :  bitflip scan: tried=56656 same_key=10 nonzero_ret=0 crashes=0
BRQC-128:  bitflip scan: tried=30752 same_key=14 nonzero_ret=0 crashes=0
BRQC-256:  bitflip scan: tried=53008 same_key=10 nonzero_ret=0 crashes=0
BRQC-512:  bitflip scan: ...       same_key=2
```

Each `SAME KEY for flipped bit` line is one padding bit; the padding bits are independent, so
the number of equivalent ciphertext encodings is `2^(same_key)`.

## Notes

* **Random-ciphertext crash: BRA-128/256 only.** BRA-128 and BRA-256 additionally segfault
  their Augmented-Gabidulin decoder on random ciphertexts (`random ct: 30 trials,
  crashes=30`); **BRA-512 does not crash**, and BRQC does not crash (robust). Neither the
  crash nor its absence affects the malleability break.
* **The single-bit scan is serial, not "seconds".** The exhaustive single-bit-flip scan is
  a serial loop of one forked decapsulation per flip (~39 ms/flip on our machine), so a full
  scan of a whole ciphertext takes minutes to hours depending on `|ct|` (tens of thousands of
  bits). The *break itself* is one query: once the padding bytes are known, target only those
  bits (`./audit 5 0 0 1013,2027`) and it is immediate. The full scan is only the exhaustive
  confirmation that the padding bits are the sole malleable positions.
* Implementation-level only. Fix: `memcmp` the received `ct'` bytes in the FO check and hash
  them in the KDF, or reject ciphertexts whose padding bits are non-zero.
