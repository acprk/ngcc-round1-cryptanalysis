# One-signature key recovery of Tins

A secret-witness recovery against **Tins** (ICCS NGCC round-1 signature, a TCitH / MPCitH
scheme over the Normalized Subfield Bilinear Collision problem). From the public key and a
**single** signature, the attack recovers the full signing witness `(alpha, beta)`, verified
on the submitters' own KAT vectors at all three levels against the **unmodified** reference
implementation.

## Why it works (one paragraph)

Tins builds its GGM / BAVC seed tree so that each node should be derived from its parent seed
(spec Alg. 4: `(seed_l, seed_r) = Encrypt_lambda(parent_seed, .)`). The reference
`ChildNodeGen` in `bavc_commit.c` instead computes `pseudoXOF(salt XOR (3 || idx || b))` and
**never uses the parent seed** (its own comment reads `// TODO: use encryption rather than
XOF`). This is present in all nine implementations (reference / optimized / additional, at
128/256/512). Consequently every tree node, including the `tau` leaf seeds that the signature
is supposed to keep hidden, is a public function of the `salt`, and the `salt` is transmitted
in the signature. The attacker therefore reconstructs all party seeds, recomputes every share,
and reads the witness directly from the auxiliary value, `alpha = aux XOR sum_i share_i` (and
likewise `beta`). One signature suffices; the witness satisfies the NSBC relation for the
public key, so it is exactly the signing secret and universal forgery follows.

## Threat model and purity

EUF-CMA. The adversary sees the public key and one honest signature (here taken straight from
the submitters' KAT). The recovery reads only `pk` and the signature bytes; there is no secret
input to the attacker. The demonstration verifies the recovered witness against the NSBC
relation of the public key.

## Layout

```
src/attack.c   one-signature witness recovery (KAT mode) + self-test (keygen/recover/forge)
build.sh       compile against a reference level directory (REF=)
run_all.sh     recover on the submitters' KAT vectors at all three levels
```

## Build and run

```
REFROOT="/path/to/Implementations/Reference_Implementation" \
KATDIR="/path/to/tins/Test_Vectors" ./run_all.sh
```

or one level:

```
./build.sh "/path/to/Reference_Implementation/Tins256"
./attack pk.hex sn.hex        # KAT mode: pk and one signature, as hex
```

The reference implementation is NOT bundled.

## Expected output

```
=== Tins-128 : recover (alpha,beta) from pk + one KAT signature ===
[KAT] sig bytes 3776; recovered witness satisfies NSBC: YES
=== Tins-256 : ... === [KAT] sig bytes 12980; recovered witness satisfies NSBC: YES
=== Tins-512 : ... === [KAT] sig bytes 50739; recovered witness satisfies NSBC: YES
```

## Scope and honesty

* The verified result is **complete secret-witness recovery from one signature**, reproduced
  on the authors' own KAT vectors at all three levels against the unmodified reference. The
  witness `(alpha, beta)` satisfies the NSBC relation for the public key, i.e. it is the
  signing secret.
* **Forgery** is demonstrated end-to-end at Tins-256: driving the genuine signer (Fiat-Shamir
  grinding included) with the recovered witness produces a fresh-message signature the unmodified
  verifier ACCEPTS (`verify=0`); a wrong-message control is rejected (`verify=1`). See
  `src/attack_forge256.c`. The two details the naive forger got wrong were the `h_piop` hash
  (`pseudohash(2*LAMBDA)`, not `sm3hash(256)`) and the contiguous `p_tmp` compression. Tins-128
  is obstructed by a reference `hash_t` underfill (it uses `sm3hash(256)`, its own verifier bug),
  and Tins-512 by a hash/serialization mismatch (with a latent, **non-crashing** out-of-bounds
  access in `ExpandChallengePoint`); both are level-specific reference defects that obstruct the
  *end-to-end forgery* at those two levels, not barriers to the attack itself — **witness recovery
  works at all three levels**.
* This is an **implementation** break: the specification's keyed-PRG tree is sound. Because the
  submitted KAT vectors encode the broken tree, they must be regenerated after the fix.
* Fix: derive child seeds with a keyed PRG that binds the parent seed, e.g.
  `XOF(salt || parent_seed || idx)`.
