# E — uBlockith-EM spec-literal forgery: is the DR₀ fixed point findable below 2²⁵⁶?

Scope: the **spec-literal** uBlockith-EM verifier (Chinith `Algorithm specifications.pdf`
p.68 `uBlockith.EncCstrnts`, p.68 `uBlockith.OWFConstraints`). Builds on SHORTLIST
finding #1 (block misalignment, CONFIRMED). This note answers the OPEN sub-question #1b:
having reduced forgery to "find a fixed point of the 2-round map DR₀", **can that fixed
point be found well below 2²⁵⁶?**

All numbers below come from code in `E-fixedpoint/` run on this machine; commands shown.
Nothing sent off-machine.

---

## 1. The enforced relation (re-derived from spec + code)

### 1.1 Spec pseudocode (verified verbatim)
`pdftotext -layout -f 66 -l 72 "src/Chinith/Algorithm specifications.pdf"` →
`OWFConstraints` (EM=true) and `EncCstrnts`:

- OWFConstraints line 9–10: `⟨in⟩ = ⟨w[0..N_block−1]⟩`, `⟨out⟩ = ⟨w[0..N_block−1]⟩ + pk2`.
  So `in` **is** the first witness block, and `out = in ⊕ pk2`.
- line 17: `⟨w̃⟩ = ⟨w[ℓke .. ]⟩`; EM ⇒ ℓke = 0 ⇒ `w̃ = w` (the whole witness, which itself
  begins with the block `in`).
- EncCstrnts line 6: `⟨w⟩⋆ = ⟨in⟩ ∥ ⟨w̃⟩ ∥ ⟨out⟩`. Because `w̃[0] = w[0] = in`, the augmented
  state is
  `w⋆ = in ‖ in ‖ S2 ‖ S4 ‖ … ‖ S22 ‖ out` — **14 blocks, indices 0..13**, and
  **blocks 0 and 1 are the identical committed value ⟨w[0..255]⟩** (they cannot be
  decoupled by the prover).
- EncCstrnts line 7: `for i∈[0..R−2] step 2` (R=24 ⇒ j = i/2 = 0..11). Each iteration
  encodes `DoubleRound_j(block_j) = block_{j+1}` where DoubleRound_j = round(2j+1)∘round(2j)
  under public round keys `k̄[2j], k̄[2j+1]` (lines 9–20 = round 2j: AddKey, S-box, linear
  mix, PL/PR; lines 21–23 add `k̄[2j+1]`; lines 24–40 meet the target block through the
  inverse of round 2j+1 and the InvSubWord constraint). Confirmed against the reference
  code `ublock_constraints.c: ublock_SSS_enc_constraints_prover` (steps 6–41) and
  `ublockith_ublock_256.c:181,190` (`in = w[0]`, `w̃ = w`).

### 1.2 Consequences (spec-literal)
- **j = 0** reads block_0 and block_1, which are the SAME value `in`. The constraint is
  therefore `DoubleRound_0(in) = in`, i.e.
  **`DR₀(in) = in`** — a fixed point of the first two uBlock-256 rounds under the PUBLIC
  round keys `k̄[0], k̄[1]` (derived from pk1 by `uBlock.KeyExpansion`). This is the only
  hard, non-free constraint tying the secret input.
- **j = 1..11** each set a *free* witness block: `block_{j+1} := DoubleRound_j(block_j)`.
  For j=11 (i=R−2) the target is block_12 = S22 with the post-whitening key k̄[24] folded
  in. All are trivially satisfiable by construction.
- The loop's largest read index is block_12 (= S22). **Block 13 = `out` = `in ⊕ pk2` is
  never read.** Hence in the spec-literal version **pk2 (= y) is entirely unconstrained**:
  a valid witness works for *any* target public key y.
  (NB: the reference *code* trims the witness to 13 blocks so its last constraint reads
  `out` and does couple pk2 — that is a *different* manifestation; this note follows the
  spec text as instructed.)
- OWFConstraints line 4 additionally imposes the degree-3 "keyspace reduction"
  `w[0]·w[1] = 0` on the first two bits of `in` (not both 1) — a 3/4-probability side
  condition on the chosen `in`, not a real obstruction.

**Exact map.** With state (X0‖X1), X0,X1 ∈ ({0,1}³²)⁴, one round is
`Xi[w] ⊕= rk`; per-byte 4-bit S-box; per word-pair linear mix
`b^=a; a^=b⋘4; b^=a⋘8; a^=b⋘8; b^=a⋘20; a^=b`; then byte permutations PL (on X0)
and PR (on X1). `DR₀ = round_{k̄[1]} ∘ round_{k̄[0]}`. Forgery ⇔ solve `DR₀(x)=x`.

### 1.3 Reduction demonstrated in the clear
`spec_witness.py` implements a faithful cleartext evaluator of the spec-literal
`EncCstrnts` o-vector (key schedule, S-box, PL/PR, their inverses, and InvSubWord — all
cross-checked: key schedule rk0/rk1 match the C library; the inverse round exactly
recovers S-box inputs). For an **arbitrary** `x` (not a fixed point) and two different
**arbitrary** `pk2`, building the honest chain and evaluating all 12 constraints:

```
$ python3 -c "import spec_witness as S,random; ... S.reduction_demo(pk1,x,pk2)"
failing constraint indices j: [0]
DR0(x)==x ? False  (j=0 constraint)
=> Only j=0 fails; it is exactly DR0(x)=x. All j=1..11 pass for ARBITRARY pk2.
```

So: **spec-literal EM forgery for any message and any target key y ⇔ a single DR₀ fixed
point.** (If `x` is a fixed point, all 12 constraints hold ⇒ by QuickSilver soundness a
cleartext-satisfying witness ⇒ accepting proof.)

---

## 2. Building DR₀ from the real cipher

`dr0_oracle.c` reproduces the uBlock-256/256 key schedule + round verbatim from
`ublock_core.c`/`ublock_witness.c`/`ublock.h`. Cross-validated against the **real library**
`ublock256_256_encrypt` (linked object `ublock_core.o`):

```
$ ./dr0_lib validate
validate: 0/10000 mismatches vs real library
```

`dr0.py` re-implements DR₀ bit-exactly in Python; validated vs the C oracle:
```
$ python3 dr0.py validate ./dr0_lib <pk1>     # zero key and random key
py-vs-C DR0: 0 mismatches / 2000   (each key)
```
Concrete keys used: pk1 = 00…00 (⇒ k̄[0]=0, k̄[1]=eff00e33 77777777 0…0) and several
random pk1.

---

## 3. Searching for a fixed point — methods, costs

CNF encoding (`dr0.build_fixedpoint_cnf`): all wires carried as GF(2) linear forms; fresh
variables only at the two S-box layers; S-box table as CNF; linear layers / fixed-point
equality as native cryptominisat XOR clauses (convention verified empirically).
**Instance size: 1280 variables, 8192 CNF clauses, 768 XOR clauses.**

### 3.1 SAT (cryptominisat5)
- **Control / preimage (known-satisfiable, unique):** encode `DR₀(x)=c` for a random known
  `c=DR₀(x₀)`. Since DR₀ is a bijection, this is a pure inversion.
  → **SAT in 1.70 s**, recovers `x=x₀`. ⇒ the encoding itself is easy for cryptominisat.
- **Fixed point `DR₀(x)=x`, pk1 = 0:** `cryptominisat5 fp_zero.cnf`
  → **UNSAT in 207 s** (this key has *no* fixed point; ≈1/e of keys are fixed-point-free —
  a random permutation has 0 fixed points with prob 1/e).
- **Fixed point, random keys:** with `--maxtime 500` one random key ran to the cap
  (`INDET/timeout, 500.51 s`). Four random keys under `--maxtime 2400 --polar rnd`
  (distinct seeds 11–14, run in parallel, ≤4 cores): **none resolved — neither SAT nor
  UNSAT — through ≥ 921 s of wall time each** before being stopped to free the shared
  machine.

The contrast is the key data point: the **same encoding** solves a 2-round *inversion* in
1.7 s but does **not** solve the 2-round *fixed point* in 500–≥921 s. The hardness is
intrinsic to the self-referential constraint, not an encoding artifact.

### 3.2 Algebraic degree / Gröbner feasibility
Algebraic degree of `x ⊕ DR₀(x)` over GF(2): theoretical bound **≤ 9** (two 4-bit S-box
layers, each of degree 3, separated by a linear layer). Empirically (Möbius transform of
each of the 256 output coordinates restricted to random 16-dim affine input subspaces,
`degree.py`): max restricted degree 3–4, mean ≈ 3 — moderate but genuinely nonlinear.
In the natural algebraic model with intermediate S-box-layer variables the system is
**quadratic** (degree 2) in ~512 GF(2) variables, or a **dense cubic** system in the 256
variables `x` alone.

Direct Gröbner/XL on this is expected to be infeasible, and worse than brute force: the
map is near-fully diffusing over the 2 rounds (measured avalanche: a 1-bit input flip
changes on average 22/256 output bits after round 1 and 115.6/256 after DR₀ — close to the
ideal 128), so the 256 equations are dense. A semi-regular determined dense system of 256 quadratic/cubic equations in 256 GF(2)
unknowns has degree of regularity a constant fraction of n, giving an F4/F5 cost far
exceeding 2²⁵⁶. (Not run to completion — flagged as the natural but non-viable next step.)

### 3.3 Structural / MITM
`DR₀(x)=x ⇔ R₀(x) = R₁⁻¹(x)`. Applying the round-1 inverse-linear map gives
`S(x⊕k̄[0]) ⊕ A·S⁻¹(A·x) = A·k̄[1]` with `A = L⁻¹∘P⁻¹` a fixed **dense** linear map. The
first term is nibble-local in `x`; the second is `A∘S⁻¹∘A` — dense. There is no partition
of the 256 state bits into two halves that lets one output block depend on only half the
unknowns via each side, because the byte permutations PL/PR + the mix diffuse `x`
near-completely over the two rounds (avalanche 22→116/256; §3.2). No meet-in-the-middle with < 2¹²⁸ memory / < 2²⁵⁶ time is apparent.
The S-box has **no fixed point** (S(i)≠i for all i), so there is no "all-nibbles-fixed"
structural solution to seed a cheap search.

### 3.4 Fixed-point count and the search problem
DR₀ is a permutation of {0,1}²⁵⁶. Its number of fixed points is ≈ Poisson(1): a solution
exists for ≈ 1−1/e ≈ 63% of keys (pk1=0 is one of the ≈37% with none). When one exists it
is essentially unique, embedded with no exploitable structure ⇒ locating it is the generic
"find the fixed point of a strong permutation" problem, i.e. ~2²⁵⁶ evaluations by search.

**Empirical search summary:** preimage (unique, known target) 1.7 s SAT; fixed point pk1=0
UNSAT 207 s (no solution for that key); fixed point, 5 random keys: 1 hit the 500 s cap and
4 unresolved through ≥921 s. No fixed point was obtained by any demonstrated method.

---

## 4. Verdict

> **SUPERSEDED by §E2 (follow-up).** The "not below 2²⁵⁶ / inconclusive" conclusion below
> reflects *naive whole-instance SAT only*. §E2 shows a hybrid guess-and-determine attack
> that finds the fixed point at ≈ **2¹³⁵** ≪ 2²⁵⁶. Read §E2 for the final verdict
> (break_score revised 1 → **3**).

- **Reduction (spec-literal):** *CONFIRMED, demonstrated in the clear.* A spec-literal
  uBlockith-EM forgery for **any message and any target public key y** exists **iff** one
  can exhibit a single `x` with `DR₀(x)=x`; `pk2` is unconstrained. (This is the exact
  "1b" claim; it is real at the level of the written spec.)

- **Is that fixed point findable below 2²⁵⁶?** *Not by any method demonstrated here.*
  - A 2-round *inversion* is trivial (1.7 s), but the *fixed point* resisted cryptominisat
    for 500–≥921 s across 5 keys (see §3.4).
  - Generic Gröbner/XL is infeasible (dense, full diffusion) and would exceed 2²⁵⁶.
  - No MITM / structural shortcut below generic is apparent; the S-box has no fixed point.
  - The problem is the generic fixed-point search of a strong permutation ≈ 2²⁵⁶.

  **A SAT timeout is INCONCLUSIVE, not a proof of 2²⁵⁶-hardness** (CDCL is not an optimal
  solver). What is solid: (i) the reduction is exact and pk2 is free; (ii) the naive
  encoding is *not* the bottleneck (inversion is instant); (iii) no sub-2²⁵⁶ algorithm was
  found. The honest position: the spec-literal forgery is a real **soundness/correctness
  defect of the written spec**, but it does **not** yield a demonstrated forgery, and the
  available evidence points to the exploit costing ≈ 2²⁵⁶.

- **Cheapest next method to try** (if pursuing further): a **hybrid guess-and-determine +
  algebraic** step — fix g bits of the middle state `m=R₀(x)` and solve the residual
  degree-2 system per guess (crossbred / BooleanSolve style), or a dedicated F4 on the
  512-variable quadratic model with a block/bipartite (p,q) ordering. Both are expected to
  remain ≥ 2²⁵⁶ for a fully-diffusing 2-round map but are the natural escalation.

### break_score (vector E): **1**
The block-misalignment spec bug is real (independently CONFIRMED as SHORTLIST #1: it
already breaks *correctness* — honest EM signatures are rejected — and leaves pk2 out of
the spec constraints). But **this specific forgery vector does not produce a feasible
attack**: it bottoms out at finding a fixed point of a strong 2-round permutation, for
which no sub-2²⁵⁶ method was demonstrated and the evidence points to ~2²⁵⁶. So E adds a
documentation/soundness finding, not a practical break. (The overall Chinith dossier score
is driven by the CONFIRMED spec defects #1–#4, not by this exploit path.)

### Reproduce
```
cd Chinith-attack/E-fixedpoint
gcc-11 -O2 -w -DHAVE_LIB -I<ref>/utils_ublock -I<ref> dr0_oracle.c ublock_core.o utils.o -o dr0_lib
./dr0_lib validate                                  # 0/10000 vs real cipher
python3 dr0.py validate ./dr0_lib 00..00            # 0/2000 py vs C
python3 solve_fp.py 00..00 zero                      # UNSAT 207 s  (no fixed point)
python3 -c "import solve_fp; ..."                    # preimage: SAT 1.70 s
python3 degree.py                                    # algebraic degree probe
python3 -c "import spec_witness as S; S.reduction_demo(pk1,x,pk2)"   # only j=0 fails
```

---

## E2 — Guess-and-determine / hybrid attack on DR₀(x)=x

**This section revises the E1 verdict.** A hybrid guess-and-determine attack finds the DR₀
fixed point at cost ≈ **2¹³⁵**, far below 2²⁵⁶. E1's "no method beats 2²⁵⁶" was the
*inconclusive* result of naive whole-instance SAT; guessing a fraction of `in` collapses
the residual.

### Method
- **Planted instances** (so a fixed point exists and is known): treat k̄[0],k̄[1] as
  independent, pick random `x`,k̄[0], set `k̄[1] = L(S(x⊕k̄[0])) ⊕ S⁻¹(L⁻¹(x))` (L = the
  round linear layer = mix∘PL/PR; S = nibble S-box). Then DR₀(x)=x by construction.
  `dr0.plant()`; **verified 6/6 against the C oracle** (`dr0_self dr0k <rk0> <rk1> <x>`).
- Fix `g` bits of `x` to the planted values (unit clauses on the E1 CNF: 1280 vars,
  8192+768 clauses) and solve the residual with cryptominisat5. Guess-set **structures**
  tried: (a) X0 branch first, (b) X1 branch first, (c) **nibble-spread** across both
  branches, (d) random. `T_ref = 9.30·10⁻⁸ s/DR₀-eval` (`dr0_self bench`: 2·10⁷ evals /
  1.86 s). Cost exponent `C(g) = g + log₂(T_wrong(g)/T_ref)` (the 2^g wrong guesses each
  cost a rejection T_wrong; the one correct guess costs T_correct ≲ T_wrong).

### Which structure — and why
Threshold g at which the residual stops being easy (3 planted instances, cap 120 s):
`c` (nibble-spread) ≈ 108–112 ≪ `a`/`b` (one branch) ≈ 144 < `d` (random) ≈ 160.
**Nibble-spread wins** because the fixed-point equation couples the two 32-bit words of
every word-pair through the mix `M` (b^=a; a^=b≪4; …); fixing bits in *both* branches of
each pair lets the S-box + linear relations propagate and either determine the rest or hit
a contradiction fast. Mechanism (cryptominisat conflicts, correct guess, structure c):
**g=128 → 950 conflicts, g=112 → 56 k, g=96 → 629 k** — near-propagation collapse at
g≳128, exponential search below ~112.

### Cost curve C(g)  (structure c, wrong-guess = rejection time)
| g | T_correct | T_wrong (reject) | C(g) = g+log₂(T_wrong/T_ref) |
|----|-----------|------------------|------------------------------|
| 160 | 0.05 s | 0.03 s | 178.3 |
| 144 | 0.04 s | 0.03 s | 162.3 |
| 128 | 0.05 s | 0.03 s | 146.3 |
| 120 | 0.17 s | 0.17 s | 140.8 |
| 112 | 1.20 s | 5.03 s | 137.7 |
| 108 | 3.1 s  | 18.0 s | **135.5** |
| 104 | ~100 s (2/3 hit 100 s cap) | ~100 s | ≳134 (cap-limited) |
| ≤100 | > 400 s cap | > 400 s cap | not reliably measurable |

**Minimum ≈ 2¹³⁵·⁵ at g ≈ 108** (guess ~42 % of `in`, nibble-spread). Below g≈104 the
residual exceeds the 400 s cap, so the curve cannot be pushed lower reliably; the minimum
is a shallow basin near g≈104–112, cost ≈ **2¹³⁴–²¹³⁸**. Either way **≪ 2²⁵⁶**.

### Falsification (all pass)
- **Wrong value ⇒ fast UNSAT** (so the 2^g factor, not rejection cost, dominates): at
  g=128 all-flip, random-wrong, and (below) real-key fixes all reject in **0.03 s**.
- **Planted not easier than real:** a REAL key (pk1=e7ee…022b from E1), random-fixed at
  g=160 and g=128, rejects UNSAT in **0.03 s** — identical to planted wrong-guesses. So the
  measured T_wrong (hence C(g)) transfers to real keys; the planted construction only
  guarantees a solution exists, it does not make the CNF easier.
- **Rejection is the cost driver and it is cheap** for g≳112; the correct guess resolves
  even faster, so C(g) is governed by T_wrong.
- Caveat: T_wrong at the *minimum* (g≈108) is calibrated on planted instances; the
  planted≈real equality was directly checked at g≥128 and is assumed to hold at g≈108.

### Algebraic residual
The CNF solved by cryptominisat *is* the exact GF(2) polynomial system (S-box table
clauses + XOR-linear layers); CDCL+Gaussian elimination solving it in 0.03–3 s with
<10³ conflicts at g≳128 already demonstrates the residual is near-linear once ~half of `in`
is fixed. A separate Sage/F4 Gröbner run was deprioritized as redundant given this direct
evidence and the wall-clock budget; it is the natural corroboration if pursued.

### Revised verdict
- **Is the DR₀ fixed point findable below 2²⁵⁶?  YES.** Hybrid guess-and-determine (fix
  ~108 nibble-spread bits of `in`, solve the residual) finds it at **≈ 2¹³⁵** DR₀-evaluations
  — about **2¹²⁰× below** the claimed 256-bit security. Combined with §1.3 (forgery ⇔ one
  DR₀ fixed point, pk2 free), the **spec-literal uBlockith-EM scheme admits a universal
  forgery, for any message and any target public key, at ≈2¹³⁵** for the ≈63 % of keys whose
  DR₀ has a fixed point.
- This is a security-level break of the *written spec*, not a 2⁶⁴/practical break: 2¹³⁵ is
  far below 2²⁵⁶ but not executable. (The reference *code*, which reads `out`, additionally
  couples pk2 and is a separate case.)

### break_score (vector E, revised): **3**
The spec-literal EM parameter set is claimed at the 256-bit level (Category-equivalent) but
its actual forgery cost is ≈2¹³⁵ ⇒ the claimed security level is not met (below the claimed
category). Not 4/5: the 2¹³⁵ attack is demonstrated only by extrapolation of the measured
cost curve (per-guess residual timed directly; the full 2^g enumeration is not executed),
and it exploits the spec-literal reading (the shipped code differs). The underlying
misalignment defect remains independently CONFIRMED (SHORTLIST #1).

### Reproduce (E2)
```
cd Chinith-attack/E-fixedpoint
python3 -c "import dr0,random; ..."        # dr0.plant(); verify vs ./dr0_self dr0k
python3 e2_worker.py c                      # structure sweep a/b/c/d
python3 e2_focus.py 128,120 w               # correct+wrong T(g), structure c
python3 e2_falsify.py                       # planted-vs-real, random-vs-flip wrong
python3 e2_refine.py 108 rA                 # cap-400 minimum refinement
```
