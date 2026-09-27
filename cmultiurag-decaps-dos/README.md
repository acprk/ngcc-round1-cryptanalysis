# Decapsulation denial-of-service in C-Multi-UR-AG

A remote denial-of-service against **C-Multi-UR-AG** (ICCS NGCC round-1 rank-metric KEM,
third member of the BRA/BRQC family). A single flipped bit of an otherwise honest
ciphertext makes the **unmodified reference decapsulation crash** (SIGSEGV) at Level-256:
about 74% of single-bit flips and 100% of random ciphertexts kill the process.

## Honest scope

This is a memory-safety **denial-of-service**, not a key recovery and not an IND-CCA
break. Unlike its siblings BRA and BRQC, C-Multi-UR-AG does **not** admit the padding-bit
ciphertext malleability: its matrix serializations are byte-exact
(`MAT_NN2_BYTES + MAT_N1N2_BYTES + salt = |ct|` with no spare bits), and an exhaustive
single-bit scan at Level-128 finds no same-key equivalent ciphertext. The rank-metric
(DIBRSD/RSL) hardness is untouched. We flag one open cryptanalytic concern separately
(see Notes): the parameters sit right at the generic MaxMinors wall with no margin for the
scheme's own multi-syndrome (Rank Support Learning) structure.

## Why it crashes (one paragraph)

Decapsulation decodes with an Augmented Gabidulin decoder. When the received word lies
outside the decoding radius, `rbc_qpoly_left_div2`'s loop `while (rtmp->degree >= b->degree)`
makes no progress (the remainder degree never drops), while its counter `int i` keeps
decrementing and is passed as the `uint32_t p2_degree` argument of `rbc_qpoly_mul2`. At
`i = -1` this wraps to `0xFFFFFFFF`, so the inner `for (j = 0; j <= p2_degree; ++j)` walks
off both operands and reads/writes out of bounds, segfaulting. An off-path attacker who
flips one ciphertext bit in transit thus kills the decapsulating process. Level-128 and
Level-512 do not crash in our scans, but the same unbounded loop is one allocation layout
away from the same fate. Fix: bound the loop with a guard counter (as BAG-Loong's
`qpoly_left_div` does) and make the degree argument signed and range-checked.

## Threat model and purity

Off-path DoS: the attacker only needs to flip a bit of a ciphertext in transit; no secret
is used. The auditor (`src/kem_audit.c`) runs each tampered decapsulation in a forked child
so crashes are counted rather than killing the run; it reads no secret key beyond the
honest keypair it generates.

## Layout

```
src/kem_audit.c   generic ICCS-KEM auditor: roundtrip + single-bit ct scan (same-key? crash?)
                  + random-ct decaps, each tampered decaps in a forked child
build.sh          copy reference level, build its objects (KAT target), link the auditor
run_all.sh        audit CMultiURAG-128/256/512
```

## Build and run

```
REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
```

or one level:

```
./build.sh "/path/to/Reference_Implementation/CMultiURAG-256" 256
./audit 3 120 10
```

The reference implementation is NOT bundled; `build.sh` builds a copy and never edits it.

## Expected output

```
=== CMultiURAG-256 ===
bitflip scan: tried=... same_key=0 nonzero_ret=0 crashes=~74%
random ct: 10 trials, crashes=10 nonzero_ret=0
=== CMultiURAG-128 ===   bitflip scan: ... crashes=0
=== CMultiURAG-512 ===   bitflip scan: ... crashes=0
```

## Notes

* Parameters over q=2, rank metric; Level-128/256/512. The crash is confirmed at Level-256
  (both reference and optimized); ~74% of single-bit flips and 100% of random ciphertexts crash,
  at roughly **0.6 s per faulting decapsulation** (the wall cost of the faulting decode + child
  fault). Level-128/512 show 0 crashes in our scans.
* Open cryptanalytic concern (not a demonstrated break): the single-instance generic rank-SD
  cost is 2^172.8 against a claimed 2^170 at the 128-bit target, i.e. no margin, and the
  scheme's N1 syndromes sharing one support form a Rank Support Learning instance that is
  strictly easier than the single-syndrome bound the estimator models. A multi-syndrome
  MaxMinors/SupportMinors analysis could push Level-128 under its category; this is left as
  the recommended next cryptanalytic step, not claimed here.
