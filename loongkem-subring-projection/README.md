# Sub-ring projection break of LoongKEM

A decision / IND-CPA break of **LoongKEM** (ICCS NGCC round-1 semi-structured-LWE KEM). Three of
its four parameter sets work over `Z_q[X]/(X^N+1)` with `N` not a power of two, so `X^N+1` is
reducible and a `Z_q`-algebra homomorphism projects the structured public rows onto a genuine,
much lower-dimensional module-LWE instance far below the claimed security.

## Why it works (one paragraph)

The public key is `A=[[A1,A2],[A3,A4]]`, `B=A·S+E`, with `A1,A2,A3,B1` block anti-circulant over
`R=Z_q[X]/(X^N+1)` (`q=8191`) and `A4,B2,E2` unstructured. For `d | N` with `N/d` odd, `X^d+1 |
X^N+1`, and reduction `psi: R -> R_d=Z_q[X]/(X^d+1)`, `X^j -> (-1)^floor(j/d) X^{j mod d}`, is a
ring homomorphism that maps small to small (each output coefficient is a signed sum of `N/d`
inputs, so variance grows by `N/d`). Applying `psi` to the transmitted structured rows
`b1 = A1 s1 + A2 s2 + e1` yields `psi(b1) = psi(A1)psi(s1) + psi(A2)psi(s2) + psi(e1)`, a
legitimate module-LWE instance of secret dimension `(k1+k2)·d`. For Loong128 (`N=12`, `d=4`) this
is dimension 208 with noise sigma ~ 4.6, whose primal-uSVP cost is far below `2^128`;
distinguishing it from uniform breaks decision-SLWE, hence IND-CPA. The attack uses only `A1,A2,b1`
and never touches the unstructured block. The only power-of-two set (Loong256, `X^16+1`
irreducible) is immune.

## Scope (honest)

This is a **design-level, semantic-security (IND-CPA) break**, not a full original-key recovery:
`psi(s)` is recoverable (the small `s2` block, `k2·d=16` coefficients, is guessable in `~2^37`),
and the recovery pipeline is validated at reduced scale, but lifting to the full
`(k1+k2)·N`-dimensional secret needs the co-factor instance at the claimed security. The fix is a
ring choice (power-of-two `N`), not a code patch.

## Threat model and purity

IND-CPA / decision-SLWE. The attack reads only the public key. The harness dumps a real key from
the reference keygen and includes the secret so the ring-hom identity and the projected noise can
be scored; `project_loong.py` uses the secret only to check the identity, never to run the
projection. The reference implementation is NOT bundled.

## Layout

```
src/dump_loong.c        key-dump harness: links the unmodified reference, verifies negacyclic
                        multiplication, and writes a real Loong128 key (A1,A2,b1,s) to dump.txt
src/project_loong.py    applies psi, checks the ring-hom identity on the real key, and reports the
                        projected MLWE instance (dimension, noise); reads the secret only to score
src/estimate_loong.py   lattice-estimator cost of each projected instance (Loong128/384/512):
                        derives the projected (dim, m, sigma_e, sigma_s) from the reference
                        params + sqrt(N/d) scaling + compression rounding, then runs primal-uSVP
                        (headline) with BDD and dual cross-checks; needs the lattice-estimator repo
                        (LATTICE_ESTIMATOR, default ~/xzy/lattice-estimator) and Sage
src/recover_reduced.py  reduced-scale EXACT recovery (dim 40 and 55) validating the recovery
                        pipeline: builds a scaled-down, psi-projected block-anti-circulant MLWE
                        with a self-planted secret and recovers it by primal (Kannan) embedding
                        + BKZ (fpylll, block sizes 20/30), verifying against the planted secret
src/sample_dump.txt     a real-key dump (fallback so the projection can be shown without a rebuild)
run_all.sh              build the harness against REF, dump a key, then run (2) projection identity,
                        (3) estimator, (4) both reduced-scale recoveries; writes logs/ (see below)
logs/                   projection_identity.log, estimate_loong.log, recover_dim40.log,
                        recover_dim55.log  (produced by run_all.sh)
```

## Build and run

```
REF=/path/to/Implementations/Reference_Implementation/Loong128 ./run_all.sh
```

The harness needs the reference `KEM_Loong.c`, `poly.c`, `auxfunc.c`, `drng.c`; `project_loong.py`
needs Sage (`sage -python`). If a live build is unavailable, `run_all.sh` falls back to the bundled
`src/sample_dump.txt`.

## Expected output

```
ring-hom check psi(b1-As)==psi(b1)-psi(A)psi(s): True
projected noise psi(e1): sigma~4.6   (model sqrt(N/d))
projected secret psi(s): dim=208
projected MLWE instance: secret dim (K1+K2)*d = 208, equations K1*d = 192
NOTE: only A1,A2,b1 used; unstructured A4/B2/E2 block never referenced.
```

## Notes

* Parameters: `q=8191`, `N=12/16/20/24` across Loong128/256/384/512; projection degree
  `d=4/immune/4/8`.
* Measured lattice-estimator cost of the projected instances (`estimate_loong.py`, classical `rop`,
  primal-uSVP headline / BDD / dual):
  * Loong128 (dim 208, sigma_e~4.85, m=192): primal-uSVP **2^76.6** (beta=168), BDD 2^73.2,
    dual 2^79.5  vs claimed 128
  * Loong384 (dim 320, sigma_e~3.76, m=288): primal-uSVP **2^107.2** (beta=277), BDD 2^103.5,
    dual 2^112  vs claimed 384
  * Loong512 (dim 720, sigma_e~2.65, m=640): primal-uSVP **2^208.1** (beta=636), BDD 2^203.8,
    dual 2^218  vs claimed 512
  All three fall far below the claimed level, so IND-CPA is broken; Loong256 is immune.
* Reduced-scale recovery (`recover_reduced.py`): EXACT recovery of the planted projected secret at
  dim 40 (BKZ-20, ~1.3 s) and dim 55 (BKZ-30, ~5.5 s). Peak RSS is ~195 MB (dominated by the
  Sage/Python runtime; the fpylll reduction data itself is well under 1 MB).
* Fix: use a power-of-two cyclotomic (`X^N+1` irreducible) at every level, or prove hardness of the
  projected instance for every divisor `d | N` with `N/d` odd.
