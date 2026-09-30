# AFS-KEX (pMAKE-BW): replayable initiator credential, unbound identities, and a failure oracle

Protocol-layer verification for three findings against **AFS-KEX** (ICCS NGCC round-1 KEX
submission; the mutually-authenticated four-pass protocol **pMAKE-BW** instantiated over
BW-KEM). All three are demonstrated on the submitted C128/C256/C512 reference primitives,
200/200 trials each, with the passing controls that rule out a broken harness.

These are **protocol/design-level** findings about the specification (Fig. 3) and its claims.
They are **independent** of the wrapper key-reuse issue already acknowledged by the authors
(the uniform wrapper generating the ephemeral key once as long-term state — reported on
ngcc.dev as kex-02-1). We do not restate that here.

## The findings

**1. The initiator's authentication credential `(cpk_A, seed_A)` is replayable.**
In round 3 the initiator A sends `c_seed^A = K_ENC^A xor seed_A` *before* it has authenticated
the responder. Any responder — including one with an uncertified key — knows `K_A` (it
encapsulated to `cpk_A`) and `K_B` (it decapsulates `ct_B` under its own composite key), so it
recovers `seed_A`. The pair `(cpk_A, seed_A)` is session-independent, because `cpk_A` is sent in
round 1 before any responder contribution exists. Once harvested, it is a reusable proof that
"`cpk_A` is Alice's". If a responder's in-session `K_A` then leaks, an attacker replays the old
`cpk_A` to Bob, uses the leaked `K_A` to complete round 3, and **Bob accepts peer = Alice while
the attacker knows `K_SESSION`** — using **no secret of Alice**. The no-leak control is rejected.
This is exactly the "compromise the encapsulated `ss`" scenario the authors' 2026-09-22 forum
post says AFS-KEM prevents "as the successful AFS-KEM based authentication also needs the
knowledge of ephemeral secret key seed that is however held by Alice herself." The seed is not
held by Alice alone: she discloses it to every responder. (`src/replay_impersonate.c`)

**2. Identities are not bound to the session key (unknown-key-share by public-key copy).**
`K_SESSION = PRF(K_A, K_B)`; `id_A, id_B` travel in the clear and enter no KDF and no MAC. An
adversary E registers a *copy of Alice's public key* under `id_E`, relays an A<->B session, and
rewrites `id_A -> id_E` in round 3. Then **A believes it shares a key with Bob, Bob believes it
shares a key with Eve, and both keys are equal.** E uses only Alice's *public* key.
(`src/uks_keycopy.c`)

**3. (support) The decapsulation success/failure bit is available to an unauthenticated peer.**
A completes round 3 whenever its decapsulation succeeds, before authenticating the peer, so a
responder with an uncertified key learns per session whether a chosen ciphertext decapsulated
under `cpk_A`. This is the oracle the spec's §2.7/§3.2 DFA-resilience argument assumes away.
We inject a failure by flipping one ciphertext byte and confirm the bit is observable (honest
200/200 vs injected-failure 0/200). This is a **remark on the argument**, not a mounted attack;
see "Scope and limits". (`src/failure_oracle.c`)

**Refutation checks (`src/negatives.c`).** From COMPASS experience we also checked two things that
turn out to be **clean** here, and we publish the negatives so reviewers do not re-walk them: the
N=512 NTT matches schoolbook multiplication mod `x^N+1` (no COMPASS-#22-style port bug), and the
CBD sampler reaches every coefficient position with a binomial histogram.

## Relation to the formal model (important)

Findings 1 and 3 sit **outside** the paper's security model: §9.1 lets `RevealEph` reveal only
`seed`, and assumes encapsulation randomness is erased. The proofs are therefore **not
contradicted** — what fails is the *informal claim* that AFS-KEM authentication is "similar to
signature-based". In SIGMA-style signing, Alice's signature covers the peer's fresh contribution
and cannot be replayed. Finding 2 is excluded by the model's Setup (Sec 8.2), where the challenger
generates all static keys; a real PKI cannot force a signature-style proof of possession for KEM
public keys, and §1.3 (item 5) claims identities are "bound to the resulting session transcript",
which the KDF does not do.

## Scope and limits

- We found **no** break of the underlying MLWE parameters, and claim none.
- Findings 1–2 are demonstrated on our own spec-faithful implementation of Fig. 3 built from the
  submitted primitives — **not** on the shipped wrapper, which does not implement Fig. 3.
- Finding 3 is an argument gap plus an observable oracle, not a completed decryption-failure
  attack. With the spec's stated `delta_AFS = 2^-67.98` (C128), the first failure needs ~2^68
  sessions absent boosting; the C128 margin against the usual 2^64-query convention is ~4 bits.
  We did not independently recompute `delta_AFS`. One factor in the scheme's favour (unstated in
  the spec): the fresh `ID(cpk)` forces any failure-boosting search to be online.

## Build and run

The reference implementation is **NOT** bundled. Point `REFROOT` at the submission's
`Implementations and Test_Vectors` directory:

```
REFROOT="/path/to/AFS-KEX/Implementations and Test_Vectors" ./run_all.sh
```

or build one level directly (use a **space-free** path to `REF`, e.g. via a symlink):

```
make REF=/path/to/Reference_Implementation/AFS_KEX_C128 all
./negatives ; ./failure_oracle 200 ; ./uks_keycopy 200 ; ./replay_impersonate 200
```

`run_all.sh` symlinks each level to a space-free name because the submission path contains a
space. Nothing under `REFROOT` is read except the reference `.c/.h`; nothing is modified.

## Purity / scoring

No attacker code path reads any honest party's secret key. The only injected value is a
per-session **public-computation** key `K_A` in finding 1 (the "leak"), which the spec's model
assumes erased. `run_all.sh` prints an explicit control for every finding (no-leak run rejected;
key-equality checked). Randomness comes from the OS (`getrandom`); the global `drng_algorithm`
symbol is defined only to satisfy the linker for C256/C512 and is never invoked.

## Expected output

See `logs/run_all.log`. All three levels: `[NEG] CONFIRMED-CLEAN`, `[ORACLE] CONFIRMED`,
`[UKS] CONFIRMED`, `[REPLAY] CONFIRMED` (200/200, control 0/200).

## Note on an implementation-level item (not packaged here)

The reference build also has an **unseeded global DRNG**: `drng_algorithm` is defined and seeded
only in the KAT driver, so an integrator who links the library without seeding gets identical
keys across processes (three processes -> same public key, return code 0). This is an
implementation defect of the ICCS template, severity B; matching this repo's design-level scope
it is reported to the committee but not packaged as an attack here.
