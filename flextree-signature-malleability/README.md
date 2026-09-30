# FlexTree: strong forgery (sEUF-CMA) via unchecked PORS+FP padding

Given any honest FlexTree signature `sigma` on a message `M`, anyone holding only the
public key can produce a **different** signature `sigma' != sigma` on the **same** `M`.
The **unmodified vendor `crypto_sign_open`** accepts it. This works at every parameter
set (160s/f, 256s/f, 384s/f, 512s/f) in both the Reference and Optimized implementations.

**Scope, stated precisely.** This is a *strong* forgery: it breaks sEUF-CMA, meaning signatures
are malleable. It is **not** an existential forgery on a fresh message (EUF-CMA is
unaffected). It matters wherever signatures are assumed to be unique or non-malleable, e.g.
signature-derived identifiers, deduplication and replay caches, or generic compositions that
need sEUF-CMA such as signcryption or CCA transforms.

## Why it works

A PORS+FP few-time signature has a fixed-size field of `mMAX` authentication-node slots.
The octopus algorithm often needs only `m' < mMAX` nodes. The specification then says
(Sec. 1.10, "Note that when the number m' of the authentication nodes returned by the
octopus algorithm is less than mMAX, we pad the signature with (mMAX - m')·n zero bytes"):

* the signer writes zeros into slots `m'..mMAX-1` (`pors_fp_sign`);
* the verifier (spec Alg. 20/21, code `pors_fp_pk_from_sig` / `pors_compute_root_from_sig`)
  recomputes `m'` and consumes exactly `m'` slots; **nothing checks that the rest are zero**.

The padding bytes are therefore outside everything the verifier authenticates. Forced pruning
only requires `m' <= mMAX`, so most honest signatures carry padding: on average ~2–15 unused slots of
`n` bytes each in our runs. Overwriting them with any value gives a new valid signature.
Because the flaw is in the specification, a conforming implementation inherits it.

**Fix (one line):** in `pkFromSigPORS`, reject unless slots `m'..mMAX-1` are all zero (or
make the signature variable-length).

## Threat model and purity

sEUF-CMA experiment, executed entirely through the vendor API:

1. `crypto_sign_keypair`;
2. signing oracle: `N` honest `(M_i, sm_i)` via `crypto_sign` (`SK-READ`, honest signer only);
3. **the secret key is zeroed** (`memset(sk,0,...)`) before the attack phase;
4. attacker (`src/maul.c`, **public inputs only**: `pk`, `M_i`, `sm_i`) recomputes
   `m' = |octopus(H_PORS(R, H_msg(R,pk,M), ctr))|` from public values and overwrites every
   padding byte;
5. `crypto_sign_open` (vendor, unmodified) on `sigma'_i || M_i`.

Controls, all printed per run:

* (a) the honest `sm_i` is accepted;
* (b) flipping one byte of the **last used** auth node, just before the padding, is **rejected**.
  This shows that `m'` is located exactly and that only the padding is free;
* (c) the mauled `sigma'_i` with a modified message is **rejected**.

The attacker needs the vendor's static octopus routine, so `src/maul.c` does
`#include "pors_fp.c"` (the vendor file, unmodified). `build.sh` copies the vendor
directory to a temp dir and never touches it on disk.

## Layout

```
src/maul.c       public-only attacker: ft_public_auth_len() recomputes m', ft_maul() rewrites padding
src/poc_main.c   sEUF-CMA driver + controls, vendor API only
build.sh         build against ONE vendor dir (Reference or Optimized, auto-detected)
run_all.sh       all 8 sets x {Reference, Optimized}
run_log.txt      real output of run_all.sh (N=10)
```

## Build and run

```
IMPLROOT="/path/to/FlexTree/Implementations" ./run_all.sh          # N=10 per set
./build.sh "/path/to/Implementations/Reference_Implementation/Flextree-160s" ./poc && ./poc 10
```

`IMPLROOT` is the `Implementations` directory of the ICCS FlexTree submission package. It must
contain `Reference_Implementation/Flextree-*` and `Optimized_Implementation/Flextree-*`.
The vendor code is NOT bundled. The Optimized build uses `-mavx2`, so it needs an AVX2 CPU.

## Expected output

One summary line per set, for example:

```
Flextree-160s[Reference]: 10/10 honest sigs have padding (avg 104.0 B); 10/10 mauled sigs ACCEPTED by crypto_sign_open | controls: honest accepted 10/10, boundary-node flip rejected 10/10, wrong-msg rejected 10/10
```

`X/N honest sigs have padding`: a signature with `m' = mMAX` has no padding and is skipped.
It is not a failure; the attacker just waits for the next signature. Every padded signature
yields an accepted `sigma' != sigma`. The exit code is 0 only if all mauled signatures are
accepted and all controls behave. See `run_log.txt` for the full real run.

## Notes

* The number of distinct valid signatures derivable from one honest signature is
  `2^(8·n·(mMAX-m'))`. For example, one unused slot in 160s gives 2^160.
* The spec's `min(8n, ...)` security formula (eq. 3.7) concerns EUF (ITSR) and is unaffected.
  We recomputed it separately: every set meets its level at `q_sig = 2^64` with ~0 margin.
  That is not claimed as a finding here.
