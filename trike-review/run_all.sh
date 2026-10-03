#!/usr/bin/env bash
# TRIKE (kem-36) review package for our forum comment of 2026-10-01.
#   SUBROOT=".../Implementations and Test_Vectors" ./run_all.sh [long] [isd]
# Nothing under $SUBROOT is modified or copied. Builds go to out/.
#   default : KATs, items 1, 2, 3, 4 (densities), 5 (rejection rate), 6 (source sites), minor (unseeded DRNG)  ~5 min
#   long    : item 4 falsification run (implanted vs random boundary keys, scaled r = 12500, 2 x 60000 decodes)
#   isd     : Tables 9/10 recomputation (needs: pip install cryptographic-estimators)
set -euo pipefail
: "${SUBROOT:?set SUBROOT to the Implementations and Test_Vectors directory of the submission}"
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$HERE/out; mkdir -p "$OUT"; cd "$OUT"
REF=$SUBROOT/Implementations/Reference_Implementation
OPT=$SUBROOT/Implementations/Optimized_Implementation
CC=${CC:-gcc}; PY=${PY:-python3}
AVX="-DAVX512_AVAILABLE -DVPCLMUL_AVAILABLE -mavx512f -mavx512bw -mavx512dq -mavx512vl -mavx512vpopcntdq -mvpclmulqdq"
HAVE_AVX=0; grep -q avx512vpopcntdq /proc/cpuinfo && grep -q vpclmulqdq /proc/cpuinfo && HAVE_AVX=1
# build <set dir> <output> <main.c> [extra flags...]: link main.c against the unmodified submission sources
build() {
  local dir=$1 out=$2 main=$3; shift 3
  local srcs=("$dir/src/KEM_AlgorithmInstance.c" "$dir/src/decoder.c" "$dir/src/sample.c" "$dir/src/gf2x.c" "$dir/ICCS/drng.c" "$dir/ICCS/auxfunc.c")
  $CC -O2 -w "$@" -I"$dir/src" -I"$dir/ICCS" "$main" "${srcs[@]}" -lm -o "$out"
}

echo "== KAT: regenerate and compare with Test_Vectors (CRLF stripped)"
for t in ref opt; do for k in 2 5 7 9; do
  D=$REF/TRIKE-$k; F=""; [ $t = opt ] && { D=$OPT/TRIKE-$k; [ $HAVE_AVX = 1 ] && F=$AVX; }
  mkdir -p kat_$t$k; build "$D" kat_$t$k/kat "$D/tests/KAT_KEM.c" ${F:+$F}
  (cd kat_$t$k && ./kat >/dev/null)
  cmp -s <(tr -d '\r' < "$SUBROOT/Test_Vectors/KAT_KEM_TRIKE-$k.txt") <(tr -d '\r' < kat_$t$k/output/KAT_KEM_TRIKE-$k.txt) \
    && echo "  $t TRIKE-$k: identical" || echo "  $t TRIKE-$k: DIFFERS"
done; done | tee kat.log

echo "== 1. Algorithm 9 as written (sum mu^2) vs code (sum C(mu,2))"
$PY "$HERE/scripts/alg9.py" "$REF" | tee alg9.log

echo "== 2. kem_dec never frees h0: allocations vs frees inside kem_dec, then heap growth"
for t in Reference Optimized; do for k in 2 5 7 9; do
  f=$SUBROOT/Implementations/${t}_Implementation/TRIKE-$k/src/KEM_AlgorithmInstance.c
  awk -v t="$t" -v n="TRIKE-$k" '/^int kem_dec/{on=1} on&&/aligned_alloc|calloc\(/{a++} on&&/free\(/{f++; v=v" "$0} on&&/^}/{gsub(/[\t;]/,"",v); printf "  %-9s %-8s allocs=%d frees=%d h0_freed=%s\n", t, n, a, f, (v~/free\(h0\)/?"yes":"NO"); exit}' "$f"
done; done | tee sites.log
for k in 2 5 7 9; do build "$REF/TRIKE-$k" leak_ref$k "$HERE/src/leak.c"; echo "  ref TRIKE-$k: $(./leak_ref$k 200 | grep decaps=)"; done | tee leak.log
F=""; [ $HAVE_AVX = 1 ] && F=$AVX   # optimized tree: AVX-512 path if the CPU has VPOPCNTDQ+VPCLMULQDQ, else its portable fallback
for k in 2 9; do build "$OPT/TRIKE-$k" leak_opt$k "$HERE/src/leak.c" ${F:+$F}; echo "  opt TRIKE-$k: $(./leak_opt$k 200 | grep decaps=)"; done | tee -a leak.log
build "$REF/TRIKE-2" leak_asan "$HERE/src/leak.c" -O1 -g -fsanitize=address
ASAN_OPTIONS=detect_leaks=1 ./leak_asan 3 2>&1 | grep -m2 -E "Direct leak|#[0-9]+ .*kem_dec" | tee asan.log || true

echo "== 3. ICCS DRNG state width"
grep -H "define SEEDLEN" "$REF"/TRIKE-*/ICCS/drng.h | sed "s|$SUBROOT/||" | tee drng.log
$PY "$HERE/scripts/bias.py" | sed -n '/DRNG/,$p' | tee -a drng.log

echo "== 4. boundary weak-key classes: density x measured bound vs claimed DFR (spec formulas)"
$PY "$HERE/scripts/wk2.py" | tee wk2.log

echo "== 5. weak-key rejection rate rho (shipped thresholds, full parameters)"
for k in 2 5 7 9; do $CC -O2 -w -I"$REF/TRIKE-$k/src" "$HERE/src/rej.c" -o rej$k; ./rej$k 20000 15; done | tee rej.log

echo "== 6. secret-indexed loads and variable-time compare (source sites)"
grep -nHE 's\[idx_to >> 3\]|in_64 \+ shift_64 \+ i\)|shift_64 = |gf2x_shift\(.*idx|memcmp\(vec1' \
  "$REF/TRIKE-2/src/decoder.c" "$OPT/TRIKE-2/src/gf2x.c" "$OPT/TRIKE-2/src/decoder.c" "$REF/TRIKE-2/src/KEM_AlgorithmInstance.c" 2>/dev/null | sed "s|$SUBROOT/||" | tee sidechannel.log || true

echo "== minor: unseeded global drng_algorithm, three independent processes"
build "$REF/TRIKE-2" rng2 "$HERE/src/rng.c"
for i in 1 2 3; do ./rng2 | grep "call#1"; done | tee rng.log

if [[ " $* " == *" long "* ]]; then
  echo "== 4 (long). implanted f=6 vs random keys, both passed through the weak-key filter, scaled r=12500"
  $CC -O3 "$HERE/src/scaled3.c" -lm -o scaled3
  ./scaled3 wkrand 12500 60000 101 & ./scaled3 wk 12500 60000 201 6 & wait
fi
if [[ " $* " == *" isd "* ]]; then
  echo "== Tables 9/10 (CryptographicEstimators)"; $PY "$HERE/scripts/est2.py" | tee est2.log
fi
