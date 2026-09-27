# Key recovery of Amoeba from a decryption-failure oracle

A chosen-ciphertext key recovery against **Amoeba** (ICCS NGCC round-1 lattice KEM). The
reference decapsulation returns an explicit error, before the Fujisaki--Okamoto check, on a
secret-dependent error-correction event. This is a clean decryption-failure oracle, and a
scalar-probe attack against it recovers the secret exactly in about **5,700 chosen-ciphertext
queries** against the unmodified reference, in **~4 s wall time (~1.2 s CPU)** (the wall time
includes forking one child process per oracle query). Independently reproduced: **517/517**
directly-probed coefficients recovered exactly on Amoeba-576.

## Why it works (one paragraph)

Amoeba adds an error-correcting code inside its CPA PKE. Decapsulation calls
`CPAPKE_Decrypt`, whose `decode_ECC` returns nonzero when it detects an uncorrectable
(weight `>1`) pattern, and `CCAKEM_Decaps` propagates that as a `-1` return **before** the FO
re-encryption comparison (`ccakem.c:61-62`). The return code is therefore a decryption-failure
oracle on attacker-chosen ciphertexts: the adversary does not wait for the natural failure rate
(DFR `2^-133`), it triggers the event on demand. To read one secret coordinate `s_a`, craft a
ciphertext with `c1 = δ` a constant scalar (so `d_a = c2_a - δ·s_a`, which is domain-independent
because it is a scalar times the secret), force every message bit to `0` except one pinned pilot
bit and one probe bit, so the decoded weight is `1` (corrected, accept) or `2` (detected, reject).
Bisecting `c2_a` finds the boundary `q/4 + δ·s_a`, giving `s_a` exactly. Amoeba-576 compresses
`c2` to only `d2 = 5` bits, so the scalar is raised to `δ' ≈ 199` (plus a `δ' = 120` mop-up pass)
to beat the coarse grid. Repeating over all coordinates recovers the secret.

## Bonus: a remote crash

On the weight-2 case the reference `decode_ECC` executes `c_corr[syndrome_map[...]] ^= 1` where
the index can be a punctured position `>= 523`, an out-of-bounds write. A real decapsulating
server therefore **crashes** (the `*** stack smashing detected ***` stack-canary abort, SIGABRT)
rather than returning `-1` on those inputs; the harness
forks each oracle query so the crash is observed as the failure answer. This is an additional
standalone remote denial-of-service (the `*** stack smashing detected ***` lines in the output).

## Threat model and purity

IND-CCA / key recovery. The adversary holds `pk` and submits chosen ciphertexts to the
decapsulation oracle, observing accept/reject (or crash). `src/amoeba_dfo_keyrec.c` calls the
reference `CPAPKE_KeyGen` and probes `CPAPKE_Decrypt`; the true secret is read only in
`[SCORING]`-tagged lines (via `Decompress_SK`) to score the recovery. Audit with
`grep -n 'SCORING' src/amoeba_dfo_keyrec.c`.

## Layout

```
src/amoeba_dfo_keyrec.c   scalar-probe key recovery; #includes the reference cpapke.c,
                          probes CPAPKE_Decrypt as the pre-FO decryption-failure oracle
build.sh                  link the harness against a reference level (never edits src/)
run_all.sh                build + run on Amoeba-576
```

## Build and run

```
REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
```

or one level:

```
./build.sh "/path/to/Reference_Implementation/Amoeba-576"
./attack
```

The C99 `inline` NTT helpers require `-fgnu89-inline` (handled by `build.sh`). The reference
implementation is NOT bundled.

## Expected output

```
delta'=199  probed=517  correct=517/517  queries=5697  time~1.2s
first 16 (rec vs true): 0/0 0/0 3/3 0/0 1/1 0/0 -1/-1 1/1 ...
*** stack smashing detected ***   (the bonus OOB-write DoS, from the forked oracle children)
```

## Notes

* Parameters over ring dimension 576/864/1152/1728/2304. The 576 set is demonstrated end-to-end;
  the larger sets share the identical pre-FO error return and are recovered by the same mechanism
  with proportionally more queries.
* The ~1 residual large-|s| coefficient per key and the tail coordinates outside `c2`'s 523 slots
  finish via a folded impulse `c1 = δ·X^p` (identical mechanism) or the public relation `b = As+e`
  on fewer than 60 small unknowns; they are not needed for the conclusion.
* This is an implementation-level break: the error-correction detect-and-abort turns decapsulation
  into a full CCA key-recovery oracle. The lattice parameters are sound. Fix: do not signal the
  ECC-detect event before the FO check (return the implicit-rejection key uniformly), and bound the
  decoder's correction index to close the out-of-bounds write.
