# qube-opt-unseeded-prng — QUBE: the optimized implementation never seeds its PRNG (publicly reproducible keys)

**Scope: implementation-level (severity B in this repository's A/B split; Critical class in the ngcc.dev
policy, same mechanism as kem-17-1).** It affects the **Optimized_Implementation** only (all four sets it
builds: QUBE-128/256/384/512). The **Reference_Implementation is not affected**: it draws from the ICCS API
DRNG (`Reference_Implementation/qube-*/src/common/kem.c:26`). This package backs our Round-1 public comment
on QUBE (kem-33).

## What we claim (and verified)

1. **Mechanism.** In `Optimized_Implementation/src/common/kem.c`, key generation (`seed_kem`, `seed_pke`,
   `sigma`, lines 55-58) and encapsulation (`m` and the salt, lines 137-138) call `prng_get_bytes()`. That
   function squeezes the file-scope SHAKE-256 context `shake256_prng_ctx` (`src/common/symmetric.c:15`, a
   plain zero-initialised `uint64_t ctx[26]`). Its only initialiser `prng_init()` is called from
   `benchmark/benchmark_kem.c:87` and `tests/qube-test.c:51`, never on the API_PKC path
   (`kem_qube.c` -> `crypto_kem_*`). The `get_random_number(...)` lines in `kem.c:60-64` are commented out,
   and `kem_qube.c` only carries the template's commented hint. The ICCS harness seeds `drng_algorithm`,
   which this tree never reads. The doc comment in `kem.c` still says the PRNG "must be seeded with
   prng_init() ... see main_qube.c"; no `main_qube.c` is shipped. The optimized tree ships no KAT file, so
   the defect cannot surface through vector comparison.

2. **Keys, ciphertexts and session keys do not depend on the API DRNG at all.** The ICCS KAT harness is run
   twice per set, with the harness nonce `"seed"` and `"ZZZZ"`. The `Seed =` lines differ, but PK, CT and SS
   are byte-identical in all 10 records of all 4 sets (`logs/kat_compare.txt`, step [1]). The per-ciphertext
   salt is identical too, so the salt countermeasure is void in this build.

3. **Controls.** (a) The same harness with a one-function patch that makes `prng_get_bytes()` draw from
   `drng_algorithm` (`patches/seed-prng-from-drng.patch`): PK, CT and SS change with the nonce in all 4 sets
   (step [2]). (b) The unmodified reference implementation (QUBE-128, QUBE-512): PK, CT and SS change with
   the nonce (step [3]).

4. **Key recovery and session-key recovery, from public data only** (`logs/attack.txt`):
   - Step [4]: an attacker process calls `crypto_kem_keypair` (no secret input), obtains the public key of
     KAT record 0 of the victim's `"ZZZZ"` run, and decapsulates that record's CT to its SS. 4/4 sets.
   - Step [5], every process seeds the API DRNG from `/dev/urandom`, as a correct integrator would.
     (a) Alice generates her key with the unmodified code; Bob (patched code, real randomness) encapsulates
     to her. The attacker runs keygen in its own process, gets Alice's pk **and sk**, and decapsulates Bob's
     ciphertext to Bob's session key. (b) Carol's key is honest (patched code). Dave encapsulates to her
     with the unmodified code. The attacker, knowing only Carol's pk, runs the public encapsulation in its
     own process and obtains Dave's ciphertext and session key. Carol's real sk is used **only for
     scoring** (it confirms that Dave's session key is the one Carol derives). So the sender side is broken
     even when the recipient's key is sound. 4/4 sets, all YES.

## What we do not claim

- Nothing about the QUBE design or the reference implementation. The fix is a one-line change of the
  randomness source (see the patch); with it, the optimized code behaves as expected (step [2]).
- In a long-running process the shared stream advances, so the k-th key or encapsulation of a process is
  the k-th output of one fixed stream. An attacker enumerates k. The demo only uses the first operation of
  each fresh process.

## Precedent

ngcc.dev kem-17-1 (HEP-QC), Critical: "Key generation draws from a file-scope SHAKE-256 PRNG context that is
never initialized by the KEM wrapper." Same mechanism. kem-17-1 is in a reference implementation; this one
is in the optimized implementation only.

## Run

```bash
REF=/path/to/QUBE/Implementations ./run_all.sh     # ~2 min, mostly compilation
```

`REF` must contain `Optimized_Implementation/` and `Reference_Implementation/` from the ICCS submission
package. Nothing under `$REF` is modified: trees are copied to `./work/`, and the KAT nonce edit, the extra
CMake target (`src/tool.cmake`, linking `src/qube_tool.c` against the unmodified `core_opt_N` object
library) and, for the control only, the patch are applied to the copies. Build output goes to
`work/*.build.log`; results to `out/`. The logs in `logs/` come from one run on Ubuntu 22.04, gcc 9.5, cmake 4.4.

## Files

| file | purpose |
|---|---|
| `run_all.sh` | builds 4 optimized variants (orig/patched x nonce) + reference control, runs steps [1]-[5] |
| `src/qube_tool.c` | keygen / enc / dec / KAT-record-0 recovery; seeds the API DRNG from `/dev/urandom` first |
| `src/tool.cmake` | the extra CMake target appended to the copied `CMakeLists.txt` |
| `patches/seed-prng-from-drng.patch` | the fix, used for control (a) |
| `logs/` | output of one complete run |

This analysis was prepared with AI assistance; every result above comes from running the submitted code.
