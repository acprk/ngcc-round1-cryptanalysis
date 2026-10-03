#!/usr/bin/env bash
# TRIKE (kem-36): scaled multi-ciphertext message search on the unmodified reference code.
#   REFROOT=/path/to/Implementations/Reference_Implementation ./run_all.sh
# Nothing under $REFROOT is modified or copied; only get_random_number() is supplied by us.
# 9 single-core jobs in parallel; ~10 min wall on a 2026 x86-64 (TRIKE-5 ref Encaps ~29 ms).
set -euo pipefail
: "${REFROOT:?set REFROOT to the TRIKE Reference_Implementation directory (contains TRIKE-2, TRIKE-5, TRIKE-9)}"
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$HERE/out; mkdir -p "$OUT"
CC=${CC:-gcc}; CFL="-O3 -march=native -w"
for s in 2 5 9; do R=$REFROOT/TRIKE-$s
  sha256sum "$R/src/KEM_AlgorithmInstance.c" "$R/src/sample.c" | sed "s|$REFROOT/||" >> "$OUT/sha256.txt"
  $CC $CFL -I"$R/ICCS" -Dget_random_number=iccs_get_random_number -c "$R/ICCS/drng.c" -o "$OUT/drng$s.o"
  $CC $CFL -I"$R/src" -I"$R/ICCS" "$HERE/src/mtv.c" "$R/src/KEM_AlgorithmInstance.c" "$R/src/decoder.c" \
      "$R/src/sample.c" "$R/src/gf2x.c" "$R/ICCS/auxfunc.c" "$OUT/drng$s.o" -lm -o "$OUT/mtv$s"
done
# TRIKE-5: B = 10, T = 2^0..2^5, 24 trials each (slope of log2 work vs log2 T)
for t in 0 1 2 3 4 5; do "$OUT/mtv5" 10 $t 24 $((100+t)) > "$OUT/t5_B10_T$t.log" & done
"$OUT/mtv5" 13 6 8 300 > "$OUT/t5_B13_T6.log" &
"$OUT/mtv9" 8 2 6 900  > "$OUT/t9_B8_T2.log" &
"$OUT/mtv2" 10 2 10 200 > "$OUT/t2_B10_T2.log" &
wait
grep -h SUMMARY "$OUT"/*.log
python3 "$HERE/src/fit.py" "$OUT" | tee "$OUT/fit.txt"
