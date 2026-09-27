# Public-key-only universal forgery of Facto-DSA

A universal forgery against **Facto-DSA** (ICCS NGCC round-1 multivariate signature). From the
**public key alone** we recover the hidden kernel on which the cubic public map degenerates, and
inverting the resulting quadratic forges a signature for any message that the **unmodified
reference verifier accepts**. Demonstrated end-to-end at level 128; no secret key, no signing
queries.

## Why it works (one paragraph)

The public key is `m` cubic forms `P_1..P_m` in `r = 2n` variables over `F_q` (`q = 65519`). The
trapdoor is a hidden linear map `L_2` whose kernel `K_2 = ker L_2` is an `n`-dimensional subspace on
which `P` degenerates to a quadratic the signer can invert. The submission prices key recovery as
brute force over a hidden vector (`q^n = 2^160/2^272/2^512`). Instead, restrict the public cubics to
a random `(n+1)`-dimensional affine chart `z = W*(u,1)`: because `K_2` meets the chart in a
projective line (`n + (n+1) - 2n = 1`), the restricted system of `m` cubics in `n` variables has a
Groebner-computable variety whose points lift to `K_2`. The correct point `v` is certified
**publicly** by `dim ker DP_v = n` and `P` vanishing on `ker DP_v` (no secret needed). On the coset
`c_0 + span(K_2)` the public map is quadratic; solving `P(c_0 + w*K_2) = h` for a hashed message `h`
yields a preimage `z` with `P(z) = h`, i.e. a forgery. The true cost is the restricted solving
degree (`d_reg = 10` at level 128, measured), not `q^n`.

## Threat model and purity

EUF-CMA, zero signing queries. The attack uses only the public key and the message digest. `tool.c`
and `verify.c` `#include`/link the **unmodified** reference `SIG_AlgorithmInstance.c` to expose
keygen, hash-to-field, and verify on the command line; the secret key is used only by an optional
cross-check (`check_k2.m`), never to guide the recovery or the forgery.

## Layout

```
src/pk2magma.py       export the public key (public data only) to Magma
src/grobner_k2.m      recover K2 = ker L2 from the PUBLIC KEY via a restricted Groebner basis
src/forge4.m          forge a signature on the degenerate quadratic coset
src/grobner_k2_256.m  the level-256 variant of the K2 recovery
src/tool.c            keygen + hash-to-field harness (#includes the reference)
src/verify.c          calls the unmodified reference verifier on a candidate signature
run_all.sh            end-to-end level-128 break + reference-verifier check
```

## Build and run

```
REF="/path/to/Reference_Implementation/Facto-DSA-128" ./run_all.sh
```

Requires `gcc`, `python3`, and **Magma** (for the Groebner step). The reference implementation is
NOT bundled; `run_all.sh` compiles the harness against it and never edits it.

## Expected output

```
=== 2. recover K2 ...        (~11 min)
=== 3. universal forgery ... (~3 min)
=== 4. verify ...            rc 0  (forged signature ACCEPTED by the reference verifier)
```
A signature forged for a fresh message is accepted; a changed message is rejected.

## Notes

* Parameters: `(n,m) = (10,13)/(17,32)/(32,62)`, `r = 2n`, `q = 65519`, for Facto-128/256/512.
* Level 128 is demonstrated end-to-end (K2 recovery ~11 min at solving degree 10, forgery ~3 min).
  Levels 256 and 512 are **mechanism-identical**, but the K2 recovery is heavier: a live level-256
  run reached F4 step degree 8 before exhausting a 180 GB memory budget (consistent with the
  estimated `2^65`), and level 512 is estimated at `2^111`. These are computationally out of reach
  on a 251 GB machine; level 128 stands as the demonstrated break.
* This is a design-level break: the "one hidden vector" security floor is wrong because `K_2` has an
  unpriced algebraic recovery path from the public key. The fix requires a hidden subspace that
  resists a restricted-Groebner recovery, i.e. re-pricing key recovery against this attack rather
  than against a `q^n` enumeration.
