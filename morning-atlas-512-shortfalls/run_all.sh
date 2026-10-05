#!/usr/bin/env bash
# MORNING-ATLAS (sign-15): challenge space, message representative and key-seed width vs the
# claimed 256/512-bit levels, plus challenge-sign-word malleability.
#   REF=/path/to/MORNING-ATLAS/Implementation ./run_all.sh
# REF must contain Reference_Implementation/ and Optimized_Implementation/ from the ICCS package
# (MORNING-ATLAS.zip, SHA-256 c796b106...c8c1). Nothing in $REF is modified: each parameter-set
# tree is compiled as is, together with src/atlas_tool.c; the two scaled experiments interpose on
# vendor functions with `ld --wrap` instead of editing them. Runtime ~2-4 min. Requires gcc, python3.
set -euo pipefail
: "${REF:?set REF to the MORNING-ATLAS Implementation directory}"
HERE=$(cd "$(dirname "$0")" && pwd); W=$HERE/work; OUT=$HERE/logs
rm -rf "$W"; mkdir -p "$W" "$OUT"
CC=${CC:-gcc}; CF="-O2 -std=gnu99 -mavx2 -w -fcommon"
SRCS="polyvec.c packing.c poly.c rounding.c auxfunc.c drng.c"

build() { # $1 tree (Reference|Optimized)  $2 level  $3 name  $4.. extra flags
  local t=$1 l=$2 o=$W/$3; shift 3; local d=$REF/${t}_Implementation/lwrdsa$l
  ( cd "$d" && $CC $CF -I. "$@" -o "$o" SIG_lwrdsa$l.c $SRCS "$HERE/src/atlas_tool.c" ) 2>"$o.log" \
    || { echo "build failed: $o (see $o.log)" >&2; exit 1; }
}
for t in Reference Optimized; do for l in 128 192 256 512; do build $t $l ${t:0:3}$l; done; done
for l in 256 512; do build Reference $l mu$l -DWRAP_XOF -DMU_TRUNC=5 -Wl,--wrap=pseudoXOF
                     build Reference $l sd$l -DWRAP_RNG -Wl,--wrap=get_random_number; done

{
echo "== [1] challenge-set size: specification parameters vs shipped code (exact)"
python3 "$HERE/src/challenge_space.py"
echo
echo "== [2] shipped challenge(): byte-wide position index (20000 random inputs per set)"
for t in Ref Opt; do for l in 256 512; do printf "  %s  " $t; "$W/$t$l" chal 20000; done; done
} | tee "$OUT/challenge.txt"

{
echo "== [3] mu = CRH(tr||M) is 48 bytes in every set; scaled demo with mu truncated to 5 bytes"
echo "       (only the mu output is truncated, via --wrap=pseudoXOF; keygen/sign/verify are unmodified)"
for l in 256 512; do "$W/mu$l" mucoll; done
} | tee "$OUT/mu_collision.txt"

{
echo "== [4] keygen seed width (DRNG draws observed via --wrap=get_random_number)"
for l in 256 512; do "$W/sd$l" seed 14; done
} | tee "$OUT/seed.txt"

{
echo "== [5] challenge sign word: unused bits are never read (all sets, Reference and Optimized)"
for t in Ref Opt; do for l in 128 192 256 512; do printf "  %s  " $t; "$W/$t$l" mal; done; done
} | tee "$OUT/malleability.txt"

echo "== [6] source pointers"
grep -n "define CRHBYTES\|define SEEDBYTES" "$REF/Reference_Implementation/lwrdsa512/params.h" | head -2 | sed 's/^/  params.h:/'
grep -n "b = outbuf\[pos++\]\|while(b > i)" "$REF/Reference_Implementation/lwrdsa512/SIG_lwrdsa512.c" | sed 's/^/  SIG_lwrdsa512.c:/'
grep -n "get_random_number(&drng_algorithm, seedbuf" "$REF/Reference_Implementation/lwrdsa512/SIG_lwrdsa512.c" | sed 's/^/  SIG_lwrdsa512.c:/'
