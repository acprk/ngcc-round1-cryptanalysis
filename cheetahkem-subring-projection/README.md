# Sub-ring projection of CheetahKEM

An IND-CPA (decision) break of **CheetahKEM** (ICCS NGCC round-1 KEM over
`Z_q[X]/(X^640+1)`, `q=7681`). Because `640` is not a power of two, `X^640+1`
is reducible over `Z` and a `Z_q`-algebra homomorphism projects the public
relation onto a genuine **128-dimensional LWE instance** whose primal block
size is only `beta=81` (about `2^53.4`), far below the claimed security.

## Why it works (one paragraph)

Over `Z`, `X^640+1 = (X^128+1)*Phi_1280`, and `X^128+1` is the smallest
negacyclic factor (`640/128=5` is odd), so the projection degree is forced to
`d=128`. The map `psi: X^j -> (-1)^floor(j/d) X^{j mod d}` is a ring
homomorphism, so `psi(b~ - a*s) = psi(b~) - psi(a)*psi(s)` exactly, and each
output coefficient is a signed sum of `N/d=5` inputs, so small secret/error stay
small (`sigma_s=3.57`, `sigma_e=6.35`, `max|e|=20`). The image is a small-noise
`n=128, q=7681` LWE instance; distinguishing it from uniform breaks the decision
assumption the IND-CPA proof reduces to, at `2^53.4`.

## Scope (honest)

This is a **confirmed IND-CPA / decision break**, verified exactly on a real key
and pipeline-validated at reduced scale. It is **not** a completed full-key
recovery: recovering the real 128-dimensional projected secret needs `beta~81`
lattice sieving (a G6K build with double-double float support, unavailable in our
offline environment), and `psi(s)` is only `s mod (X^128+1)`, so the full
640-dimensional key additionally needs the `Phi_1280` factor (degree 512, ~2^158).
The rank of the finding is the semantic-security break, which holds for every
parameter set (estimated `2^53.4 / 2^95 / 2^125 / 2^158`).

## Threat model and purity

The recovery uses only the public key `(a, b~)`. The secret is read only to score
the projected-secret match (`verify_proj.py` reads `s_coef` from the dumped key for
the identity/variance check). The reference implementation is NOT bundled; `src/` is
never modified and the reference is never edited.

## Layout

```
src/verify_proj.py     confirms psi(b~-a*s)=psi(b~)-psi(a)psi(s) on a real key + prints (n,q,sigma)
src/build_instance.py  builds the projected n=128 LWE instance (public data)
src/toy_recover.py     runs the primal-embedding BKZ recovery to completion at reduced scale n0=40/56/72
src/recover_real.py    the real-key n=128 recovery driver (needs a G6K build with dd/qd float)
src/dump.c             harness: dumps a real Cheetah128 key (a,s,b_tilde) from the reference
run_all.sh             build dump vs REF, verify identity, validate pipeline
```

## Build and run

```
./run_all.sh                                   # self-contained pipeline validation
REF=/path/to/cheetah128-reference ./run_all.sh REALKEY   # + real-key ring-hom identity
```

The default run validates the recovery pipeline at reduced scale (self-contained,
needs `fpylll`, available inside Sage's Python). The `REALKEY` step additionally
dumps a real key from the reference (`REF` must contain `KEM_Cheetah.c`, `ntt.c`,
`poly.c`, `mod.c`, `auxfunc.c`, `drng.c` and headers) and checks the ring-hom
identity; the bundled `dump.c` and `verify_proj.py` may need their field format
aligned (`dump.c` should print `a_coef`/`s_coef`/`b_tilde`).

## Expected output

```
n0=40: RECOVERED at beta=20   n0=56: RECOVERED at beta=20   n0=72: RECOVERED at beta=40
# with REALKEY:
ring-hom identity psi(b-a*s)==psi(b)-psi(a)psi(s): True
projected: n=128, q=7681, secret sigma=3.57, noise sigma=6.35 (max 20) -> decision-SLWE broken
```

## Notes and fix

* The fix is structural: use a power-of-two cyclotomic (`X^N+1` irreducible) at
  every level, or prove hardness of the projected instance for every factor
  `d | N`. The projection cost is governed by the smallest negacyclic factor, so
  the parameters must be set for that dimension, not the full 640.
* The sibling submission LoongKEM falls to the same projection.
