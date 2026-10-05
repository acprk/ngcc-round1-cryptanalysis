# cretake-naxos-binding — CreTAKE (kex-03)

Two implementation issues in the CreTAKE KEX wrappers
(`Implementations/{Reference,Optimized}_Implementation/*/KEX_AlgorithmInstance.c`),
present in the archived NICCS package (`CreTAKE.zip`) in **both** the Reference and
the Optimized tree. This package backs our Round-1 public comment on CreTAKE.

Everything below is produced by running the **submitted** code: `run_all.sh` copies
each submission tree into `./work/` and builds/patches only the copy. `$REF` is never
modified.

```sh
REF=/path/to/CreTAKE/Implementations ./run_all.sh
# REF must contain Reference_Implementation/ and Optimized_Implementation/.
# Runtime a few minutes; needs gcc (AVX2 for the opt tree) and ASan for F2.
```

Our own transcript is in [`logs/run.txt`](logs/run.txt).

## F1 (Critical) — the initiator-side length-unit error removes the NAXOS binding

CreTAKE resists state leakage with the NAXOS trick `sk~ = wGen(G(ski, re))`: the
ephemeral KEM key is derived from **both** the long-term secret `ski` and fresh
randomness `re`. The spec (§4.2.1/§4.2.2) states that revealing the session state
alone does not expose the wKEM secret, and Theorems 3/4 argue the adversary cannot
compute `sk~` without both inputs. In IND-StAA/IND-AA, revealing only the session
state (not the long-term key) is a **permitted** query.

In the implementation `G` is instantiated (S2S shown; S2K identical; two call sites
per instance — `kex_generate_pass1_msg_a` and `kex_derive_ss_a`):

```c
memcpy(buf + SEED_BYTES, ska, SKI_LEN);
pseudohash(SEED_BYTES * 8, buf, SEED_BYTES + SKI_LEN, seed_kg);
```

e.g. `CreTAKE128/CreTAKE-S2S-BiT128-eZEN128/KEX_AlgorithmInstance.c:117` and `:187`.
The third `pseudohash` argument is a **bit** length
(`auxfunc.c:460 int pseudohash(int digest_len_bits, const unsigned char *msg, unsigned long long msg_len_bits, ...)`),
but the code passes the **byte** count `SEED_BYTES + SKI_LEN`. So `pseudohash`
absorbs only `(SEED_BYTES + SKI_LEN)/8` bytes: `r` in full (64 B) plus the first
**177 / 464 / 1072** bytes of `ska` at the 128/256/512 levels.

Those leading `ska` bytes are **public**. In BiT, `pack_sk` begins with the packed
public key, in the same order as `pack_pk` (the KEX code relies on this when it
recovers the peer public key with `memcpy(pkI, ska, PKI_LEN)`). Measured
`LCP(pk, sk) = 1048 / 2144 / 5056`, and `177/464/1072 <= 1048/2144/5056`, so **every**
absorbed `ska` byte is a public-key byte. The number of long-term **secret** bytes
entering `seed_kg` is **zero**:

```
seed_kg = pseudohash( r || (a public prefix of pk_i) )
```

The ephemeral key depends only on the session state `r` and on public data — the
NAXOS binding to the long-term key is gone. Given a single permitted `StateReveal`
plus the public `pk_i` and the on-wire messages, the attacker recomputes `seed_kg`,
regenerates `(tpk, tsk)`, decrypts to `k~`, and recomputes the session key. No search.

`run_all.sh` shows, for all six S2K + six S2S reference instances and the runnable
optimized instances:

- `staterev_key_recovered = N/N`, `honest_match = N/N` (the attacker's "forged sk"
  is `pk_i || random`, i.e. public data only);
- **control**: changing only this one call to `(SEED_BYTES + SKI_LEN) * 8` drops
  recovery to `0/N` while honest sessions still match `N/N`;
- `absorbed_is_public = YES` and the `LCP(pk,sk)` values above.

**De-duplication vs. kex-03-1.** kex-03-1 (ngcc.dev) already names this
initiator-side call and concludes "all 64 random bytes are still absorbed and this
second units error does not reduce entropy further". That is correct about *entropy*,
but it measures the wrong thing: the damage is the loss of the **ephemeral/long-term
binding** that NAXOS and Theorems 3/4 rely on. Relative to kex-03-1 this adds (a) a
model-internal state-reveal key recovery with no search; (b) a new affected set, S2K,
for which kex-03-1 only claimed a `2^64` weak-forward-secrecy degradation after the
complementary key is compromised; and (c) it **survives** the responder-side fix named
by kex-03-1. `run_all.sh` includes a `fix0301` variant that applies *only* that
responder fix and still recovers `N/N`. K2K/K2S are **not** affected: there the
absorbed prefix is a KEM secret key whose LCP with its public key is 0.

## F2 (Medium) — the KEX wrappers ignore caller message lengths (pre-auth OOB read)

`kex_generate_pass2_msg_b` and `kex_derive_ss_a` discard the length arguments
(`(void)m1_len_bytes;` / `(void)mb_len_bytes;`, or use them only to size a buffer)
and parse at **constant** offsets (`m1 + TPK_LEN`, `m2 + C_TILDE_LEN`, …). No instance
checks the received length. For K2S/K2K the first message carries no signature, so
this is a **pre-authentication** path. The clearest case is K2S:

```c
tpk = calloc(m1_len_bytes, 1); memcpy(tpk, m1, m1_len_bytes);   // buffer size = attacker length field
// ... PKE_Encrypt then reads TPK_LEN bytes from tpk
```

Built under ASan with each buffer sized to exactly the bytes received (what a real
network receiver does), truncated `m1`/`m2` give an invalid-memory READ in all 150 cases (25 instances x {m1,m2} x 3 lengths): 148 heap-buffer-overflow, 2 heap-use-after-free; no OOB write. Typical:

```
READ of size 615  poly_publickey_unpack (ZEN_128/poly.c:496)
                  <- pke_enc <- kex_generate_pass2_msg_b:148
```

All reads; no out-of-bounds write observed. If the caller pre-allocates with
`kex_get_total_msg_len_bytes()` (as the shipped `test_correctness` does), the overflow
does not occur but a short message is still processed as complete. Fix: validate the
received length against the expected length before splitting.

## Files

- `run_all.sh` — copies the submission trees, builds against them, runs F1 (state
  reveal + control + `fix0301` de-dup + LCP witness) and F2 (ASan).
- `src/attack_state.c` — F1: honest session vs. single `StateReveal` recovery, attacker
  using only public data.
- `src/attack_state2.c` — F1 variant with the "forged sk = pk || garbage" input made
  explicit.
- `src/lcp.c` — prints `LCP(pk, sk)` and whether the absorbed `sk` prefix is public.
- `src/poc_trunc.c` — F2: feeds an `L`-byte prefix of `m1`/`m2` to the responder/initiator.
- `logs/run.txt` — our run against the archived NICCS package.

Prepared with AI assistance; every number comes from running the submitted code.
