# ternary3-timing — reproduce the NEV CT-1 timing channel

The vendor sources are **not** bundled. Point the variables at the submission's own trees
(all set dirs in a tree are byte-identical apart from the Makefile; `-DPARAMS=1..12` picks the set):

    export REF=/path/to/NEV/Implementations/Optimized_Implementation/avx2/NEV-R1   # required
    export REF_REF=/path/to/NEV/Implementations/Reference_Implementation/NEV-R1    # optional (portable-C rows)

Compiler is the submission's own `/usr/bin/gcc` (11.4) with the submission's own `CFLAGS`
(`-O3 -march=native -mavx2 -mbmi2 ...`). **All timing is `taskset -c $CORE`** (default 100; set
`CORE=` to your isolated core, `CORE=none` to disable). Nothing under `$REF`/`$REF_REF` is modified:
each tree is copied into `work/<kind>-{clean,instr}` and the instrumentation patches
(`patches/instr-*.patch`, counter globals only) are applied to the `-instr` copy. Every *timing*
binary links the pristine `-clean` copy.

## One shot

    ./run_all.sh 6 12        # R3 (recommended) and C3*; add/replace PARAMS as args

## Step by step

    ./prep.sh                                        # copy REF -> work/, apply instrumentation patches
    ./divscan.sh                                     # -> logs/divscan.txt  (0 div/idiv, KyberSlash check)
    python3 brscan.py obj/avx2-p6-USE_SHA3/sample.o ternary3   # 28 jcc; the secret compare is kept

    ./build.sh avx2 6 USE_SHA3 gen                   # instrumented classifier -> bin/gen_*
    ./build.sh avx2 6 USE_SHA3 time                  # clean timer            -> bin/time_*
    taskset -c 100 ./bin/gen_avx2_p6_USE_SHA3  20000 data/cts_avx2_p6_USE_SHA3.bin 0
    taskset -c 100 ./bin/gen_avx2_p6_USE_SHA3  20000 data/tam_avx2_p6_USE_SHA3.bin 1   # tampered == rejected
    taskset -c 100 ./bin/time_avx2_p6_USE_SHA3 data/cts_avx2_p6_USE_SHA3.bin ab 2000 15
    taskset -c 100 ./bin/time_avx2_p6_USE_SHA3 data/cts_avx2_p6_USE_SHA3.bin aa 2000 15   # negative control
    taskset -c 100 ./bin/time_avx2_p6_USE_SHA3 data/cts_avx2_p6_USE_SHA3.bin bb 2000 15   # negative control

    ./build.sh avx2 6 USE_SHA3 slope
    taskset -c 100 ./bin/slope_avx2_p6_USE_SHA3 data/cts_avx2_p6_USE_SHA3.bin.all 400     # per-bucket slope

    ./build.sh avx2 6 USE_SHA3 seeds ; ./build.sh avx2 6 USE_SHA3 smp
    taskset -c 100 ./bin/seeds_avx2_p6 200000 data/seeds_p6.bin
    taskset -c 100 ./bin/smp_avx2_p6  data/seeds_p6.bin 15000                             # isolated poly_sample_r

    ./build.sh avx2 6 USE_SHA3 fvf  ; taskset -c 100 ./bin/fvf_avx2_p6 3000               # message dependence
    ./build.sh avx2 6 USE_SHA3 keys ; taskset -c 100 ./bin/keys_avx2_p6_USE_SHA3 4000     # key dependence
                                      taskset -c 100 ./bin/keys_avx2_p6_USE_SHA3 4000 dup # ... null control
    ./build.sh avx2 6 USE_SHA3 kgr  ; taskset -c 100 ./bin/kgr_avx2_p6 20000              # CT-5 retry census (0)

The `*.bin.all` dumps (one record per ciphertext tagged with its exact rejection count) are written
next to the `.bin` by the `gen_*` binaries and are needed by `slope_*`. They are large and git-ignored;
re-create them by re-running `gen_*`.

## What is invariant vs what is platform-specific

Absolute cycle counts depend on the CPU and on machine load. What reproduces anywhere:

- rejections/decap mean ~= 21.97, sd ~= 4.8; **refills 0 under SHA3** (the finding survives the spec
  primitive), ~8e-4 under the SM3 XOF;
- a **monotone, roughly linear** slope of decap cycles vs rejection count (on a quiet core, 0
  inversions over 22 buckets; on a loaded shared core you may see small local inversions);
- **sign-correct** LOW-vs-HIGH separation (15/15 batches) that is **many times** the same-class control;
- the signal survives on **rejected** (one-byte-flipped) ciphertexts;
- R1/R2/C1/C3 at the noise floor (0/16 fixed-vs-fixed pairs over threshold); no key dependence.

Reference-rig figures (Xeon Gold 6230R): slope 18.92 (P6/SHA3), 32.63 (P12/SHA3); isolated
`poly_sample_r` slope 17.56; separation +434/+504/+708/+402 cyc vs controls +0…+28 cyc.
