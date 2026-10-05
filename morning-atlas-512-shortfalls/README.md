# morning-atlas-512-shortfalls — MORNING-ATLAS (sign-15): ATLAS-512 (and ATLAS-256) fall short of their claimed levels

**Scope: specification + implementation. Certificational (no full-width attack is run); every
mechanism is shown on the unmodified submitted code, and the widths are taken from the
specification text.** This package backs our Round-1 public comment on MORNING-ATLAS (sign-15).
Package: `MORNING-ATLAS.zip`, SHA-256 `c796b106a7d43b2b3d6110ec2be426aa321cc7336f39a2cc027b2d6e8b4cc8c1`.

None of the items below is covered by ngcc.dev sign-15-1..7 (checked 2026-10-04). They are
independent: fixing any one of them leaves ATLAS-512 below 512 bits.

| # | what | sets | cost vs claim | level |
|---|---|---|---|---|
| 1 | **spec**: kappa = 60 at n = 512 gives \|ChSet\| = C(512,60)·2^60 = 2^322.67, although the spec says kappa is chosen so that \|ChSet\| exceeds the target level (Sec. 1.2, and Sec. 2.6 "Challenge size"; Table 2 lists kappa = 60 for ATLAS-512) | ATLAS-512 | 2^322.67 < 2^512 | spec |
| 1b | **code**: `challenge()` draws positions with one byte (`b = outbuf[pos++]`, `while (b > i)`), so for n = 512 positions [256, 452) are never non-zero; image <= C(316,60)·2^60 = 2^277.45 | ATLAS-512 (ref + opt) | 2^277.45 | impl |
| 2 | **spec**: mu = CRH(tr ‖ M), CRH output fixed at 48 bytes (spec "Notations and Symbols"; Alg. 2 l.4, Alg. 3 l.2), unsalted; code `CRHBYTES 48U` in all sets | ATLAS-256, ATLAS-512 | collision 2^192 < 2^256, 2^512 | spec |
| 3 | **spec**: K <- {0,1}^256 (Alg. 1 l.1) and y := Sam(K ‖ mu ‖ count) (Alg. 2 l.8) is deterministic, so guessing K against one signature exposes c·s1 = z − y; **code**: keygen draws exactly 256 DRNG bits (`get_random_number(..., SEEDBYTES*8)`) and expands rho, rho' (hence s1) and key with pseudoXOF, so pk/sk are a function of 256 bits | ATLAS-512 | 2^256 < 2^512 | spec + impl |
| 4 | unused bits of the 64-bit challenge sign word are never read by `unpack_sig`, so flipping them gives a different valid signature (field not covered by sign-15-2, which is the hint padding) | ATLAS-128/256/512 (192 has no unused bit), ref + opt | SUF-CMA only | impl |

## Why each item is a forgery / key recovery (generic attacks)

1. *Challenge guessing.* The signature carries c itself and `sig_verify` compares c coefficient by
   coefficient with H(mu ‖ w1') (`SIG_lwrdsa512.c:524-526`). Fix a target c; pick any short z, zero
   hint, compute w1' = HighBits(Az − c·t1·2^d) and hash. Each trial hits c with probability about
   1/|image|, so a fresh-message forgery costs ~2^322.67 trials with the specified parameters
   (~2^277.45 with the shipped sampler). Same class as ngcc.dev sign-15-3 (ATLAS-192, 2^188.17,
   Critical) and sign-06-5 (COMPASS-SIG, byte-wide index, Critical, not executed). The smallest
   kappa reaching 2^512 at n = 512 is 118 (Aigis-Sig+ PARAMS III, also n = 512, uses tau = 118).
2. *Collision transfer.* Find M1 != M2 with CRH(tr‖M1) = CRH(tr‖M2) (~2^192), ask for one signature
   on M1, output it for M2. The 48-byte width is stated in the specification, so it survives
   replacing pseudoXOF by an ideal XOF (same class as ngcc.dev sign-02-1, sign-06-1, sign-18-1,
   sign-01-8).
3. *Key-material enumeration.* Spec: guess K (and the small counter) for one signature on a known
   message, recompute y = Sam(K ‖ mu ‖ count); the right K is the one for which z − y = c·s1 is
   short, and s1 follows by solving c·s1 = z − y over the integers. Code: pk and sk are a
   deterministic function of one 256-bit draw; enumerate it and compare with pk.

## Reproduce

    REF=/path/to/MORNING-ATLAS/Implementation ./run_all.sh     # ~2-4 min, gcc + python3

`REF` must contain `Reference_Implementation/` and `Optimized_Implementation/`. Nothing in `REF` is
modified. The two scaled experiments interpose on vendor functions with `ld --wrap`:
`--wrap=pseudoXOF` zeroes bytes 5..47 of the **mu output only** (identified by its input length),
and `--wrap=get_random_number` counts / overrides the keygen DRNG draw. Outputs (`logs/`):

- `challenge.txt` — [1] exact \|ChSet\| for spec and code parameters; [2] 20000 challenges per set:
  ATLAS-512 has **0** non-zeros in [256,452) (uniform: 459375), 315/512 positions ever hit,
  chi²/df = 1701 (ATLAS-256: 0.8), Reference and Optimized identical.
- `mu_collision.txt` — [3] with mu truncated to 5 bytes, a collision is found from the public key
  alone (~2^20–2^21 hashes) and the single signature on M1 is accepted for M2 by the unmodified
  `sig_verify`; control M3 rejected. ATLAS-256 and ATLAS-512.
- `seed.txt` — [4] one `sig_keygen` draws exactly 256 DRNG bits in one call; the same 256 bits with
  the DRNG in two unrelated states give identical pk and sk; with 14 unknown seed bits the attacker
  recovers sk from pk by enumeration and signs with it (victim sk is read only for SCORING).
- `malleability.txt` — [5] unused sign bits 31..63 (ATLAS-128) / 60..63 (ATLAS-256/512) flip to a
  distinct accepted signature; flipping a used sign bit is rejected (control). ATLAS-192 (kappa=64)
  has no unused bit.

## What is NOT claimed

- No full-width forgery or key recovery is run (2^192 / 2^256 / 2^277 / 2^322 are counting bounds).
- ATLAS-128 and ATLAS-192 are not affected by items 1-3 (their mu, seed and challenge spaces meet
  128/192, apart from the already reported sign-15-3).
- Item 4 is SUF-CMA only.

## Suggested fixes

1. ATLAS-512: kappa >= 118 (re-derive beta1, omega, rejection rates) and a 2-byte position index
   (any index width >= log2 n).
2. CRH output >= 2·lambda bits (64 bytes for ATLAS-256, 128 bytes for ATLAS-512), or a salted /
   randomized message representative with a matching proof.
3. ATLAS-512 KeyGen: draw >= 512 bits of seed material (rho may stay 256 bits if public).
4. `unpack_sig`: reject any non-zero sign bit at index >= kappa.

This analysis was prepared with AI assistance; every result above comes from running the submitted code.
