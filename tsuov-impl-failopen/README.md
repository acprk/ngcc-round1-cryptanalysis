# TSUOV (NGCC sign-31): implementation findings, reproduction package

Target: the NICCS round-1 package TSUOV.zip (SHA-256 `7ab1effc5fe911c6ab9483ca44a9d9f6d6d911b03eee9f2873b384d97f9aee1d`).
The harness copies each submitted tree into `work/` (omitting `KAT_SIG.c`) and links the harnesses against it.
Nothing under `$REF` is modified.

```sh
REF=/path/to/unzipped/TSUOV ./run_all.sh      # REF contains Implementations/
```

Requirements: x86-64 with AVX2, gcc (gcc-11 is used if present), with AddressSanitizer support. Takes about 2 minutes.

| harness | item | expected output (logs/) |
|---|---|---|
| `src/failopen_rl.c` | 1 | `*_failopen_rl.log`: the last line `RLIMIT= 0 (0 = ACCEPT)` in all 6 trees |
| `src/failopen.c` | 1 | `*_failopen.log`: `verify(sig1, m2, len=2^62) = 0`; `sign(...)` returns 0 |
| `src/failopen_sign.c` | 1 | there is no verify→sign oracle; a failing sign re-emits a signature on the previous message |
| `src/asan2.c` | 2 | `*_asan1.log` / `*_asan2.log`: heap over-read; `*_asan3.log`: heap WRITE in `Expand_mu` (length wrap) |
| `src/probe.c` | 2, 3 | `*_probe.log` `SUMMARY ... 8/8` for each category; `crossverify.log` |

Compilation flags are those of the submitted Makefile (Reference: `-O2`) and CMakeLists (Optimized: `-O3 -march=x86-64 -mavx2`),
plus `-D_GNU_SOURCE` and `-DSIG_SALT_BITS/-DPK_SEED_BITS = 8*TSUOV_SEED_LEN`, which the harness uses to locate fields.

`logs/` holds the output of a full run on 2026-10-04.
