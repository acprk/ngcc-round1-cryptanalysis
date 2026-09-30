#!/usr/bin/env bash
# Steps 2-4: build the submitted reference tree (variant `base`) and four spec-literal
# variants of it from the SAME patched work tree, run the ICCS PQCgenKAT harness for
# all 12 sets x {ICCS, SHA3}, and diff the generated vectors against the submission's
# own Test_Vectors.
#   REF=/path/.../Reference_Implementation/NEV-C1 \
#   TV=/path/.../NEV/Test_Vectors ./run_kat.sh
#
#   variants:  base  = patched tree, NO -DSPEC_* -> must reproduce Test_Vectors byte-for-byte
#              F1    = -DSPEC_F1  (spec 3.1 Noise2Pt)
#              F2    = -DSPEC_F2  (Algorithm 11 literal CBD_eta for eta=3,7)
#              F3    = -DSPEC_F3  (Algorithm 15 nonce order: g at N=0, f' at N=1)
#              F123  = all three
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-/usr/bin/gcc}
: "${TV:?set TV=/path/to/NEV/Test_Vectors (submission KAT vectors; not bundled)}"
WORK=$("$HERE/build_common.sh")
CFLAGS="-O2 -fomit-frame-pointer -std=c99"
INC="-I. -Isymmetrics -Ispeed_test -Ikat_test"
SOURCES="poly.c ntt.c owpke.c verify.c sample.c pack.c cca.c cpa.c"
SYM="symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c"
DR="kat_test/rng.c kat_test/drng.c"
KF="kat_test/KAT_KEM.c kat_test/KEM_AlgorithmInstance.c"
LOG="$HERE/logs"; mkdir -p "$LOG" "$HERE/bin"
declare -A DEF=( [base]="" [F1]="-DSPEC_F1" [F2]="-DSPEC_F2" [F3]="-DSPEC_F3" \
                 [F123]="-DSPEC_F1 -DSPEC_F2 -DSPEC_F3" )
VARIANTS="base F1 F2 F3 F123"
cd "$WORK"
jobs=0
for v in $VARIANTS; do for p in $(seq 1 12); do for be in ICCS SHA3; do
  out="$HERE/bin/kat_${v}_${p}_${be}"
  ( $CC $CFLAGS $INC -DPARAMS=$p -DUSE_$be ${DEF[$v]} \
        $SOURCES $SYM $DR $KF -o "$out" > "$LOG/build_${v}_${p}_${be}.log" 2>&1 \
    || echo "BUILD-FAIL $v $p $be" ) &
  jobs=$((jobs+1)); [ $((jobs % 8)) -eq 0 ] && wait
done; done; done
wait
echo "built: $(ls "$HERE"/bin/kat_* 2>/dev/null | wc -l) / 120 generators"
for v in $VARIANTS; do for p in $(seq 1 12); do for be in ICCS SHA3; do
  d="$HERE/kat/$v/${p}_${be}"; rm -rf "$d"; mkdir -p "$d"
  ( cd "$d" && "$HERE/bin/kat_${v}_${p}_${be}" > "$LOG/run_${v}_${p}_${be}.log" 2>&1
    rc=$?; [ $rc -ne 0 ] && echo "RUN-FAIL $v $p $be rc=$rc" ) &
  jobs=$((jobs+1)); [ $((jobs % 8)) -eq 0 ] && wait
done; done; done
wait
echo "KAT generation done: $(find "$HERE"/kat -name 'KAT_KEM_NEV_*.txt' | wc -l) / 120 files"
echo "== differential (logs/kat_diff.txt) =="
ROOT="$HERE" TV="$TV" python3 "$HERE/cmp_kat.py" | tee "$LOG/kat_diff.txt" | \
  grep -E "reproduces 12/12|BYTE-IDENTICAL|MISMATCH" | head -14
