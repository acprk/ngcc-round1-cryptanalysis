# Static-key recovery of MAMBA-NIKE

A key-mismatch / reaction key-recovery against **MAMBA-NIKE** (ICCS NGCC round-1
non-interactive key exchange). Against a responder that reuses its static secret key,
an active initiator that sends chosen one-pass messages and observes a key-confirmation
(reaction) signal recovers the **entire static secret** against the unmodified reference
implementation.

> **Read the query count honestly.** The **71-query** figure holds **only** under the
> reference's own `-DSTATISTICAL_TEST` build, which bypasses the SHAKE256 KDF and exposes the
> **raw reconciliation string** (one bit per group) as the oracle output. Against the deployed
> API (which returns only the hashed shared secret, giving a single accept/reject bit per
> query) the cost rises to about **`2^15` queries** — this larger figure is **asserted from the
> `O(n/4)` group structure, not benchmarked**. The key-recovery conclusion is the same either
> way; the number is not.

## Scope and honest caveat

MAMBA-NIKE is named and categorized as a NIKE (a static-key primitive), but its security
proof (spec App. B.3) establishes only *passive*, single-transcript real-or-random
security, and App. B.4 explicitly disclaims active / CCA / key-reuse security. This attack
does **not** contradict the passive theorem. It breaks the security that the NIKE name and
category imply, namely security under static-key reuse against an active adversary
(Freire-Hofheinz-Kiltz-Paterson, PKC 2013). The finding is a category / claim mismatch
backed by a working full key recovery, not a refutation of the stated passive theorem.

## Why it works (one paragraph)

The reference `Derive` (static responder) applies D4 reconciliation `rec(sB * u_hat, h)`
to the attacker's one-pass message `M1 = (mu, u, h)` with no ciphertext validation and no
FO/CCA transform, reusing the same static `sB` on every call. The intermediate
`v = sB * bp` is a coefficient-domain negacyclic ring product (the reference `poly_ntt`
is a no-op), hence **linear in the static secret**, and `bp`, `h` are attacker-chosen while
the dither `du, dv` are derived only from the attacker's `mu` and are therefore known.
Choosing `bp = c0 * X^0` with `c0 in {1024, 2048, 3072}` makes each reconciliation bit a
**known `dist8` function** of four secret coefficients and the attacker's 2-bit help
pattern. One query fixes one `(c0, pattern)` for all reconciliation groups at once, so a
fixed probe set of ~71 queries yields a per-group signature that is injective over all
`(2*eta+1)^4` coefficient values; per-group maximum-likelihood decoding plus an exact
dither-subtraction refinement recovers `sB` completely.

## Threat model and purity

Active NIKE with static-key reuse. The harness holds the victim `sB`, answers only oracle
calls on attacker-chosen `M1`, and never inspects `sB`. The attacker replicas of the public
dither / encoding (`src/harness.c`) are checked equal to the reference at runtime. The oracle
is the reference's own `-DSTATISTICAL_TEST` reconciliation output (a one-bit-per-group
key-confirmation signal); no reference source is modified.

## Layout

```
src/attack.c       full end-to-end attack, MAMBA-NIKE-128
src/attack_gen.c   eta/n-generic driver (128/192/384; eta<=3)
src/harness.c/.h   attacker replicas of poly_dither / encode_b / bp_target -> u_raw
Makefile, run_all.sh
```

## Build and run

```
REFROOT="/path/to/Implementations/Reference_Implementation" NKEYS=30 ./run_all.sh
```

or one profile directly:

```
make REF=/path/to/Reference_Implementation/MAMBA-NIKE-128 attack
./attack 30
```

The reference implementation is NOT bundled.

## Expected output

```
=== MAMBA-NIKE-128 (n=1024, eta=2) ===
SUMMARY MAMBA-NIKE-128: 30/30 full recoveries, mean queries=71.0, mean time~0.29s, oracle=raw-reconciliation(reaction)
=== MAMBA-NIKE-384 (n=2048, eta=2) ===
SUMMARY MAMBA-NIKE-384: 5/5 full recoveries, mean queries=71.0, mean time~0.77s
```

## Notes

* Profiles: `n = 1024/2048`, `eta = 2/3/7/5` across 128/192/384/256/512. The **128 and 384
  profiles recover reliably** end-to-end here; the **192 profile recovers only ~60% of keys**
  (its larger/edge secret alphabet leaves some coordinates unresolved by the fixed probe set).
  256 and 512 use the identical vulnerable `nike_shareda` path and the same `v = sB * bp`
  linearity, with a larger secret alphabet that requires more scalings/probes.
* Queries are non-adaptive (a fixed probe set, one round) under the `-DSTATISTICAL_TEST`
  raw-reconciliation oracle. Under the deployed API's strict single-bit accept/reject oracle
  the count inflates by an `O(n/4)` factor to about `2^15` queries; this is an estimate from the
  group structure, not a benchmark. The key-recovery conclusion is unchanged.
* Fix: a NIKE responder must not apply reconciliation to unvalidated attacker input under
  static-key reuse. This requires a CCA transform binding the transcript (so a reaction
  signal reveals nothing about `sB`), i.e. redesigning MAMBA-NIKE to meet the active-security
  bar its NIKE category demands, not merely the passive one it proves.
