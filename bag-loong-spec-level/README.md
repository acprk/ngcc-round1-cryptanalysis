# BAG-Loong: two specification-level findings (merged support rank; the eps column)

Verification package for the public forum comment on **BAG-Loong** (ICCS NGCC round-1 unstructured
rank-metric KEM, `kem-03`). Both findings are about the **specification**, not the archived code, and
both survive the repair discussed for `ngcc.dev` **kem-03-3** (Liu, [ePrint 2026/2223](https://eprint.iacr.org/2026/2223)),
which showed that the reference sampler draws the error supports from a fixed public monomial pool.

1. **The key-recovery instance has rank `t1 + t2 - g`, not `t1 + t2`** (6/8/9/10, measured on real
   keys), while Sec. 3.3.2 / Table 5 price the error as `t1 + t2`. The key instances of the 256-,
   384- and 512-bit sets are below their claimed classical levels for every `omega` in [2,3]
   (12.7–92.4 bits), and the ciphertext (message-recovery) instances of the 384- and 512-bit sets are
   below target too — for the 512-bit set, message recovery at 2^390.0 is the cheapest path of all,
   122 bits under the claim. **No full-parameter attack is run**: this is an estimator/closed-form
   result of the same kind as the accepted `kem-26-3`, backed by a dimension measurement on real keys
   and by end-to-end recovery at reduced scale.
2. **The `eps` column of Table 1 is too small for the specification's own error distribution**, so a
   spec-conforming sampler **never decrypts**: the tail support dimension is 38/57/72/82 against
   `eps` = 33/51/66/73, exceeded in 400/400 ciphertexts, and KEM round-trips agree 0/40. The archived
   code decrypts only because of the public monomial pool that kem-03-3 reports — so the sampling
   defect is load-bearing for correctness and the two issues cannot be repaired independently. This
   answers a question that ePrint 2026/2223 Appendix B explicitly left open.

**Reference implementations are not included here.** Point `REF=` at the vendor tree from the ICCS
submission package.

## Credit to prior work

Two things in finding 2 are **not ours** and are cited as such in the comment:

- the bound `dim(V2.VY + V1.VX) <= d2.dY + d1.dX - gR.g`, whose four values are exactly 38/57/72/82,
  is **eq. (10) of ePrint 2026/2223** (Zihan Liu);
- the observation that a pool-only randomisation makes the submitted decoder fail is **Appendix B** of
  the same paper. That appendix states that its experiment does *not* settle the question, because the
  sampler used there still ignored `require_one_in_v2` and still drew `E` from `Supp(R1)`. Our
  contribution is to make the sampler conform on all three points, to verify conformance by
  measurement, and to measure the **tail support dimension** — which shows the `eps` budget is
  structurally insufficient rather than a rejection-order detail in `recover_support_basis()`.

## Quick start

```bash
REF=/path/to/BAG-Loong/Implementations/Reference_Implementation ./run_all.sh
```

## What is patched, and what is not

`src/patch_sampler.py` replaces **only** the support-pool loop inside
`sample_support_pair_logical()` in `src/loong_pke.c`, plus (variant B) the one line that draws `E`:

| variant | change |
|---|---|
| `B` (default) | pool drawn from the keygen XOF; `require_one_in_v2` honoured by placing `1` first, so `1` lands in the g-dimensional intersection and hence in `Supp(Y)`; `E` drawn from `support_r2` instead of `support_re`, per Sec. 1.2 ("we do not consider E since `Supp(E) = Supp(R2)`") |
| `A` | the same sampler change, `E` left on `Supp(R1)` as in the archived code |
| `control` | nothing — the archived tree, unmodified |

The `A_{X,Y}` / `A_{R1,E|R2}` tables, the coefficient sampling, the ciphertext encoding, the FO
transform and the augmented-Gabidulin decoder are untouched. The patch script refuses to run unless
its anchor text matches exactly once per parameter set.

Conformance of the patched sampler is checked by measurement, not assumed: `instr-B-* rank` reports
`dim Supp(X) = t1` and `dim Supp(Y) = t2` exactly, with no rank inflation (the failure mode that
ePrint 2026/2223 Appendix B observed in its own modification).

## Harness modes

`src/instr.c` `#include`s `loong_pke.c` so that the file-static helpers
(`logical_vec_decode`, `generate_public_objects`, `matrix_mul`, `pke_ct_core_decode`, ...) are
reachable; `loong_pke.c` is therefore excluded from the link. Nothing in the vendor sources is edited
by the harness.

| mode | what it does |
|---|---|
| `rank <keys>` | per key: `dim Supp(X)`, `dim Supp(Y)`, `dim(Supp(X)+Supp(Y))`, and the per-column rank of `(X_j | Y_j)`. `Y` is recomputed as `S + H*X` from the key pair. |
| `noise <keys> <ct>` | rank of the residual decryption noise `R2 Y - R1 X + E` **and** the support dimension of its tail (the `n1*n2 - n'` coordinates where the codeword is zero), against `delta` and `eps`. Computed from the secrets, bypassing the decoder. |
| `kat <keys>` | KEM keygen/encaps/decaps round-trip |
| `dump <file>` | one instance (m, n, n1, field polynomial, H, S, and the true X, Y) for an external solver |

The secret key is read only to recompute `Y` and to score recoveries (`grep` for `SCORING`-style
uses: `recover_xy`, and the ground-truth comparisons in `merged_vs_block.py`). No measurement
or guess is steered by it.

## Reduced-scale attack

`src/merged_vs_block.py` builds instances exactly as `KeyGen` does — uniform `H`, secret random
supports with the prescribed intersection, `1` in `Supp(Y)`, `n1` columns sharing the support — and
then runs two attackers through the *same* F_2 solve and the *same* unknown budget `2*n*r'`:

- `merged`: guess one subspace `F` of dimension `r'` and hope `F` contains `Supp(X) + Supp(Y)`;
- `block`: guess `F1 >= Supp(X)` and `F2 >= Supp(Y)` independently — what Sec. 3.3.2's asymptotic
  success probability `2^{-t1(m-r1)-t2(m-r2)+m}` charges for.

Recovery (`merged`): 8/8 keys at `m=9, n=10, n1=4, A=[[2,1],[1,2]]` in a mean of 2^15.84 guesses
(predicted 2^15.68), and 4/4 at `m=11, n=12` in 2^17.80 (predicted 2^18.33). "Recovered" means the
full `X`: one successful guess yields the support, after which each remaining column is a single
linear solve.

Hit rates (`prob` mode, 2*10^6 samples per item). The per-block rate is far below any practical
sample budget, so its two factors — independent by construction — are measured separately and
multiplied:

| shape | merged | per-block | advantage of merging |
|---|---|---|---|
| `m=9, A=[[2,1],[1,2]], r'=4` | 2^-15.977 (31 hits; predicted 2^-15.681) | 2^-20.503 (predicted 2^-20.555) | **2^4.53** (predicted 2^4.87) |
| `m=9, A=[[2,2],[2,2]], r'=4` | 2^-10.320 (1565 hits; predicted 2^-10.277) | 2^-20.554 (predicted 2^-20.555) | **2^10.23** (predicted 2^10.28) |

Two further shapes were run and are **not** quotable (`out/` records them as such): at
`A=[[3,2],[2,3]]` with `m=9` the merged rate is 2^-21.7, and at `m=11` it is 2^-24.7, both below the
sample budget, so their printed ratios are noise.

## Estimator

`estimator/estimate.py` prices both instances of Sec. 2.2 with CryptographicEstimators 2.1.1
(`RankSDEstimator`), at `omega` = 2, 2.81 and 3:

- key instance, eq. (1): `[2n, n]` over `F_{2^m}`, `r` = merged `A_{X,Y}` rank = 6/8/9/10
- ciphertext instance, eq. (2): `[2n+n1, n]`, `r` = merged `A_{R1,E|R2}` rank = 7/9/10/10

| set | instance | (q,m,N,k,r) | omega=2 | omega=2.81 | omega=3 | claimed |
|---|---|---|---|---|---|---|
| 128 | key | (2,47,84,42,6) | 109.2 | 131.6 | 134.9 | 128 |
| 128 | ct | (2,47,94,42,7) | 120.7 | 138.6 | 140.8 | 128 |
| 256 | key | (2,67,130,65,8) | **231.2** | **241.0** | **243.3** | 256 |
| 256 | ct | (2,67,142,65,9) | **245.7** | **255.7** | 258.0 | 256 |
| 384 | key | (2,83,166,83,9) | **320.5** | **330.8** | **333.3** | 384 |
| 384 | ct | (2,83,180,83,10) | **332.9** | **343.5** | **345.9** | 384 |
| 512 | key | (2,97,208,104,10) | **419.6** | **430.4** | **432.9** | 512 |
| 512 | ct | (2,97,223,104,10) | **390.0** | **400.9** | **403.5** | 512 |

It also prints the calibration control: the 128-bit key instance priced at rank 10 — as if the blocks
were independent — returns 2^219.9, reproducing the Table 5 PRR entry of 221.

`estimator/aght_closed_form.py` gives the closed-form AGHT cost
`(m(N-k-1))^omega * q^{r(m-t')-m}` with `t' = floor(m(N-k-1)/N)`: 124.8 / 237.1 / 320.5 / 419.6 for
the key instances at `omega = 2`, agreeing with the tool to 0.1 bit.

## What is NOT claimed

- **No attack at the real parameters was executed.** The 2^231–2^433 figures are estimator and
  closed-form costs; the executed recoveries are at `m = 9` and `m = 11`.
- **The 128-bit set is not listed as affected**: both of its instances fall below 128 only at
  `omega = 2` and clear the target at 2.81 and 3.
- **Quantum levels are not claimed to be broken.** A bare Grover-iteration count is not a valid
  argument against the call's quantum targets, so we leave the quantum column alone.
- **The multiple-syndrome (RSL) structure is not quantified.** KeyGen publishes n1 = 10–15 syndromes
  on one support, which can only help an attacker; ignoring it makes every cost above an upper bound
  on the attacker's work.
- **Finding 2 is a correctness break, not a security break**, and it is repairable by raising `eps`
  to at least the tail dimension (`eps` in [38,43] for the 128-bit set, 57/72/82 for the others — all
  within the spec's own `eps <= min(n1*n2 - n', n' - k)`), after which the DFR formula, the last
  column of Table 5 and the parameters of `G(g, n', eps+k)` need recomputing.

## Environment

gcc 11, Python 3 (no third-party modules for the harness or the reduced-scale attack; the estimator
needs `cryptographic-estimators` 2.1.1). Measurements on a 104-core / 251 GB host; nothing here is
timing-sensitive.

This analysis was prepared with AI assistance; every number above was printed by the scripts in this
package.

## Files

```
build.sh                    builds the harness against REF (variants B / A / control)
run_all.sh                  reproduces every number in the comment
src/patch_sampler.py        the conforming-sampler repair (anchored string replacement)
src/instr.c                 measurement harness (rank / noise / kat / dump)
src/merged_vs_block.py      reduced-scale recovery and the two hit-rate comparisons
estimator/estimate.py       CryptographicEstimators, both instances, three omegas
estimator/aght_closed_form.py  closed-form AGHT cross-check
```
