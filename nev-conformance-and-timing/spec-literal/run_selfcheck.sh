#!/usr/bin/env bash
# Step 1 + section 4: Algorithm-11 self-check against the submitted cbd1/cbd2/cbd4,
# the F-2 claim at eta = 3, 7, and the two Fig. 4 falsification candidates.
#   REF=/path/to/.../Reference_Implementation/NEV-C1 ./run_selfcheck.sh [trials]
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-/usr/bin/gcc}
TR=${1:-2000}
WORK=$("$HERE/build_common.sh")
mkdir -p "$HERE/bin" "$HERE/logs"
cp "$HERE/harness/selfcheck.c" "$HERE/harness/multiset.c" "$WORK/"
SRC="sample.c poly.c ntt.c pack.c symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c"
( cd "$WORK"
  for p in 1 4 5 7 9; do
    $CC -O2 -std=c99 -I. -Isymmetrics -Ikat_test -DPARAMS=$p -DUSE_SHA3 \
       selfcheck.c $SRC -o "$HERE/bin/selfcheck_$p"
  done
  for p in 4 7 9; do
    $CC -O2 -std=c99 -I. -Isymmetrics -Ikat_test -DPARAMS=$p -DUSE_SHA3 \
       multiset.c $SRC -o "$HERE/bin/multiset_$p"
  done
)
{ for p in 1 4 5 7 9; do "$HERE/bin/selfcheck_$p" "$TR"; echo; done; } > "$HERE/logs/selfcheck.txt" 2>&1
{ for p in 4 7 9; do "$HERE/bin/multiset_$p" "$TR"; done; } > "$HERE/logs/multiset.txt" 2>&1
echo "== self-check verdicts (logs/selfcheck.txt) =="
grep -h "SELFCHECK_ETA124\|PT2NOISE_LAYOUT\|FIG4_EXPLAINS" "$HERE/logs/selfcheck.txt"
echo "== multiset (logs/multiset.txt) =="
cat "$HERE/logs/multiset.txt"
