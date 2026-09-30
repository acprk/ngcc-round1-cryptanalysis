# UVW-KEM: decryption failures are a key-recovery oracle even with a constant-time decoder

UVW-KEM (NGCC round 1, KEM #38, ngcc.dev `kem-38`) decrypts by list-decoding a hidden RS code,
then solving for `r1` on a randomly chosen information set `I1`, retrying on failure (spec Alg. 5
step 10, unbounded; the code stops after 1000 attempts). ngcc.dev kem-38-2 (Markku-Juhani Saarinen) notes that failures
are visible through return codes and a large timing gap, and that the constant-time fix is to
"always do the failure path's work". This package shows that **this fix is not sufficient**:
honest ciphertexts still fail with probability about 2^-43 after 1000 retries, the failure event
depends on the secret column pairing, and "did decapsulation return my key?" alone is enough to
recover the pairing with about 2^53 queries.

## Status

- **Overall DFR: CONFIRMED by exact computation.** Our counting reproduces the spec's Theorem 2
  single-attempt values exactly (0.988123 / 0.987827 / 0.987803).
- **Pair/ratio recovery from final failures: simulated (UVW-128 size), not run against the real
  decapsulator.** 2^53 queries is inside the usual 2^64 IND-CCA budget but not practical
  (~0.15 s per decapsulation). The structure-recovery and decryption stages after the pairs are
  known are those of the 9-24 forum post by Tianyuan Xie (openHiTLS); we did not rerun them.
  UVW-256/512 are extrapolated (2x / 4x more pairs), not simulated.
- **Implementation observations** (memory leaks, shared DRNG): CONFIRMED on the unmodified
  reference code (ASan).

## Numbers (from `logs/`)

Overall DFR after A attempts (`src/dfr.py`):

| A | UVW-128 | UVW-256 | UVW-512 |
|---|---|---|---|
| 1 | 2^-6.40 | 2^-6.36 | 2^-6.36 |
| 1000 (code) | **2^-43.3** | **2^-42.1** | **2^-41.7** |

UVW-128 vs retry bound (`src/dfr_vs_A.py`): 10^4 -> 2^-63.0, 10^5 -> 2^-84.7, 10^6 -> 2^-108.3,
10^8 -> 2^-160.4. Reaching 2^-128 needs about 10^7 attempts; a constant-time decoder would have
to run all of them every time.

Why failures leak. Let t = |e|_3 be the number of hidden pairs with e1(i) = e2(i) != 0. These
positions look error-free in c11 - c12, so any `I1` that hits one fails. After 1000 attempts,
failures come almost only from t = 4..6 (`src/boost.py`). In public coordinates each such pair
is a triple (a, b, gamma) with e[a] = gamma * e[b] != 0. The attacker cannot see t, so it cannot
select failing ciphertexts offline: it encapsulates honestly (so it knows e and K) and records
the ciphertexts whose decapsulation does not return K.

Heavy-hitter recovery from failures only, UVW-128 size (`src/hh_sim.py`, failing error vectors
drawn from the exact law P(t | fail)); pairs are chosen greedily by count under the constraint
that they partition the 860 coordinates:

```
N=500  failures: greedy partition exact=416/430
N=1000 failures: greedy partition exact=430/430   (mean true count 11.7, max false 4)
```

1000 failures x 2^43.3 queries per failure = about **2^53.3 decapsulation queries**.

## Implementation observations (reference = optimized sources)

- `uvw_pke_dec` allocates `GU_I1` / `GU_I1_inv` in every retry and frees them only if malloc
  fails (UVW-256 `KEM_AlgorithmInstance.c:1312`, UVW-512 `:1313`; UVW-128 uses stack arrays).
  ASan, one honest decapsulation: 2 x 364,658 B (256), 2 x 1,455,218 B (512). A 1-byte-modified
  ciphertext runs all 1000 retries: about 0.7 GB / 2.9 GB per ciphertext
  (`logs/malformed_256_rss.txt`: 540 MB RSS after 240 s of one such decapsulation, still running).
- Every early return in `kem_dec` leaks the unpacked ciphertext (code reading; ASan shows 1,784 B per rejected UVW-128 ciphertext, not logged here).
- The `I1` choices are drawn from the global `drng_algorithm`, so decapsulation is randomized and
  advances the stream later used by `kem_keygen` / `kem_enc` (`logs/drng_*.txt`).

## Build and run

```
./run_all.sh                                            # part A: python3 + mpmath + numpy
REFROOT=/path/to/UVW_Key_Encapsulation_Mechanism/Implementations/Reference_Implementation ./run_all.sh
LONG=1 REFROOT=... ./run_all.sh                         # + malformed-ciphertext runs (minutes)
```

`REFROOT` must contain `UVW-KEM-128/256/512` from the ICCS submission package; it is not bundled.
`src/test_uvw.c` links the reference core (without `KAT_KEM.c`) and defines its own
`drng_algorithm`. The secret key is used only by the decapsulation oracle; `hh_sim.py` knows the
simulated pairing only to score the result.

## Files

- `src/dfr.py`, `src/dfr_vs_A.py`, `src/boost.py`: exact DFR computation (mpmath)
- `src/hh_sim.py`: failure-only heavy-hitter simulation (numpy)
- `src/test_uvw.c`: C harness (honest round trip, DRNG advance, malformed ciphertext)
- `logs/`: output of `LONG=1 REFROOT=... ./run_all.sh`
- `COMMENT.md`: the forum comment
