# Public-key-only universal forgery of Origami

A zero-query universal forgery against **Origami** (ICCS NGCC round-1 multivariate
signature, a "local-zone UOV" MQ scheme). From the public key alone the attack
produces, for any message, a signature that the **unmodified reference verifier
accepts**, at every parameter set (128/256/384/512).

## Why it works (one paragraph)

A UOV/Rainbow trapdoor hides its central map behind secret input/output linear
transforms `S, T`; forgery is hard because the verifier's public map is
`P = T o F o S` and only the signer knows `S, T`. Origami omits the output
transform entirely: the specification states (Section 2.6.2) that "no public output
hiding is undone during signing", and the input permutation is the **public**
`Pi_pub` derived from `seed_pk`. The verification equation is therefore exactly a
public, zone-triangular, bilinear map with no oil x oil terms and no secret change
of variables: in each zone `z`, every public equation is
`sum_{non} sum_{o} c[eq,non,o] * y[non] * y[oil_start+o]`, with all coefficients `c`
read from `SHAKE(seed_pk, ...)` or the public `R_pk`. The secret data only tells the
honest signer how to sample vinegar values; it never enters verification. So a forger
can go zone by zone: fix arbitrary vinegar values, which makes that zone's equations
**linear** in its oil coordinates, solve the linear system, and finally apply the
public permutation. No signing queries, no secret, polynomial time.

## Threat model and purity

EUF-CMA, zero queries. The forger `origami_forge_pk_only(sig, pk, digest, salt, rnd)`
reads only `pk` (expanded by the reference `pk_expand`) and the message digest. The
driver `forge_main.c` calls the reference `sig_keygen` to obtain an honest `pk`, then
**zeroes the secret key** (`memset(sk,0,...)`) before forging, so no secret material is
used. Audit with `grep -n 'sk\|secret' src/forge_append.c` (the forger has no secret input).

## Layout

```
src/forge_append.c   the pk-only forger, appended to the reference origami_ref.c
                     (it uses the reference's internal zone layout + public-map streamer)
src/forge_main.c     driver: honest keygen, zero sk, forge N messages, reference-verify each
build.sh             append + compile for one level
run_all.sh           build + forge on all four levels
```

## Build and run

```
REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
```

or one level:

```
./build.sh "/path/to/Reference_Implementation/Origami-128"
./forge 10
```

The reference implementation is NOT bundled; `build.sh` appends the forger to a *copy*
of `origami_ref.c` and never edits the reference on disk.

## Expected output

```
=== Origami-128 ===  Origami: 10/10 pk-only forgeries accepted   (~10 ms each)
=== Origami-256 ===  Origami:  8/10 pk-only forgeries accepted   (~0.57 s each)
=== Origami-384 ===  Origami:  9/10 pk-only forgeries accepted   (~7 s each)
=== Origami-512 ===  Origami: 10/10 pk-only forgeries accepted   (~5 s each)
```

Each printed trial shows `forge_rc=0 verify=0`: `verify=0` is ACCEPT by the reference
verifier. A count below 10 is the forger occasionally failing to *produce* a signature
(the tail zone's linear system is rank-deficient and the driver retries up to 8 times);
it is a forger-completeness limit, not a rejected forgery. Every signature that is
produced is accepted.

## Notes

* Parameters over `q = 16`: `(d,k) = (3,2)/(6,5)/(8,7)/(9,8)`, `(N,M) =
  (200,104)/(968,488)/(1800,904)/(2312,1160)`.
* This completely breaks EUF-CMA at every level with zero signing queries. A fix
  requires reintroducing secret input/output transforms `S, T`, which returns the
  scheme to a Rainbow/UOV design that must then withstand the intersection and
  rectangular-MinRank attacks.
* The reference and optimized implementations share the same public verification map
  (byte-identical KATs), so the forgery applies to both.
