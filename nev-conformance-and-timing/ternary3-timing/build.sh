#!/usr/bin/env bash
# Compile one CT-1 harness binary against a prepared work tree (run ./prep.sh first).
#   ./build.sh <kind:avx2|ref> <PARAMS> <backend:USE_SHA3|USE_ICCS> <which>
# which = gen | time | slope | fvf | keys | seeds | smp | kgr
# Compiler and flags are the submission's own (avx2/Makefile): /usr/bin/gcc -O3 -march=native.
# The 'gen', 'seeds' and 'kgr' binaries link the INSTRUMENTED tree (counter globals); every
# other binary links the CLEAN (pristine submission) tree and is what all timing uses.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-/usr/bin/gcc}
K=$1; P=$2; BK=$3; W=$4
F="-Wno-incompatible-pointer-types -mavx2 -mpopcnt -mbmi2 -msse2 -march=native -mtune=native -O3 -fomit-frame-pointer -std=c99 -w"
pick() { case $1 in gen|seeds|kgr) echo "$HERE/work/$K-instr";; *) echo "$HERE/work/$K-clean";; esac; }
T=$(pick "$W")
[ -d "$T" ] || { echo "missing $T -- run ./prep.sh (with REF set) first" >&2; exit 1; }
SYM="$T/symmetrics/hashkdf.c $T/symmetrics/fips202.c $T/symmetrics/auxfunc.c"
CORE="$T/poly.c $T/ntt.c $T/owpke.c $T/verify.c $T/pack.c $T/cca.c $T/cpa.c $SYM $T/randombytes.c"
mkdir -p "$HERE/bin"
I="-I$T -I$T/symmetrics -DPARAMS=$P -D$BK"
case $W in
  gen)   $CC $F $I $CORE "$T/sample.c" "$HERE/harness/gen_classes.c" -o "$HERE/bin/gen_${K}_p${P}_${BK}" -lm ;;
  time)  $CC $F $I $CORE "$T/sample.c" "$HERE/harness/time_pairs.c"  -o "$HERE/bin/time_${K}_p${P}_${BK}" -lm ;;
  slope) $CC $F $I $CORE "$T/sample.c" "$HERE/harness/time_slope.c"  -o "$HERE/bin/slope_${K}_p${P}_${BK}" -lm ;;
  fvf)   $CC $F $I $CORE "$T/sample.c" "$HERE/harness/time_fvf.c"    -o "$HERE/bin/fvf_${K}_p${P}" -lm ;;
  keys)  $CC $F $I $CORE "$T/sample.c" "$HERE/harness/time_keys.c"   -o "$HERE/bin/keys_${K}_p${P}_${BK}" -lm ;;
  seeds) $CC $F $I $CORE "$T/sample.c" "$HERE/harness/gen_seeds.c"   -o "$HERE/bin/seeds_${K}_p${P}" -lm ;;
  smp)   $CC $F $I $CORE "$T/sample.c" "$HERE/harness/time_sampler.c" -o "$HERE/bin/smp_${K}_p${P}" -lm ;;
  kgr)   $CC $F $I $CORE "$T/sample.c" "$HERE/harness/keygen_retry.c" -o "$HERE/bin/kgr_${K}_p${P}" -lm ;;
  *) echo "unknown which=$W" >&2; exit 1 ;;
esac
