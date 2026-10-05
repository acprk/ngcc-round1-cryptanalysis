#!/usr/bin/env bash
# FLIT (kem-15): the optimized verify() accepts a constant fraction of invalid
# ciphertexts, bypassing the FO re-encryption check and turning decapsulation
# into a plaintext-checking oracle.
#
#   REF=/path/to/FLIT/Implementations ./run_all.sh
#
# REF must contain Reference_Implementation/, Optimized_Implementation/ and
# Additional_Implementation/ exactly as in the ICCS submission package (or the
# MathEternal/FLIT-NGCC GitHub tree; both carry the same verify.c). Nothing in
# $REF is modified: trees are copied to ./work/ and the fix control is patched
# onto the copy only. Runtime ~2-3 min. Requires gcc with AVX2 (-march=native).
set -euo pipefail
: "${REF:?set REF to the FLIT Implementations directory}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$HERE/work; OUT=$HERE/logs; rm -rf "$W"; mkdir -p "$W" "$OUT"
TOOL=$HERE/src/flit_fo_tool.c
CC=${CC:-gcc}; CFLAGS="-O2 -march=native -w -std=c11"

# build the tool against one tree: $1 = absolute tree dir, $2 = output binary
build() {
  local d=$1 out=$2
  # keccak4x is only used by the FIPS202 trees (which ship fips202x4.h in the
  # tree root); the SM3 reference/optimized trees ship a vestigial keccak4x that
  # is not compiled or linked.
  ( cd "$d" && $CC $CFLAGS -I. -o "$out" "$TOOL" \
      $(ls *.c | grep -v '^KAT_KEM.c$') \
      $(ls *.S 2>/dev/null) \
      $( [ -f fips202x4.h ] && [ -d keccak4x ] && ls keccak4x/*.c ) )
}
# copy a submission tree into work/ under a label and build the tool there
prep() { # $1 label  $2 tree-subpath-in-REF
  local d=$W/$1; rm -rf "$d"; cp -r "$REF/$2" "$d"; build "$d" "$W/tool-$1"
}

echo "== copying and building (submission trees are copied, never modified)"
prep ref128    Reference_Implementation/FLIT128
prep ref256    Reference_Implementation/FLIT256
prep opt128    Optimized_Implementation/FLIT128
prep opt256    Optimized_Implementation/FLIT256
prep opt512    Optimized_Implementation/FLIT512
prep fopt128   Additional_Implementation/FLIT_FIPS202_OPT128
# fix control: reference idiom on the optimized tree
cp -r "$W/opt128" "$W/fix128"
patch -s -p1 -d "$W/fix128" < "$HERE/patches/verify-fix.patch"
build "$W/fix128" "$W/tool-fix128"

{
echo "########################################################################"
echo "# [0] honest round-trip (optimized FLIT128) — the defect is invisible here"
echo "########################################################################"
"$W/tool-opt128" honest

echo
echo "########################################################################"
echo "# [1] verify() accept rate on INVALID ciphertexts (should be 0 for a"
echo "#     correct constant-time equality check: every differing pair -> reject)"
echo "########################################################################"
for t in opt128 opt256 opt512 fopt128; do echo "-- $t (optimized)"; "$W/tool-$t" acc; done
for t in ref128 ref256; do echo "-- $t (reference, control)"; "$W/tool-$t" acc; done
echo "-- fix128 (optimized + patches/verify-fix.patch, control)"; "$W/tool-fix128" acc

echo
echo "########################################################################"
echo "# [2] verify()/cmov micro-behaviour (optimized FLIT128 vs reference)"
echo "########################################################################"
echo "-- opt128 (optimized): verify mismatch returns -1; cmov with b=0xFF moves only bit 0"
"$W/tool-opt128" ct
echo "-- ref128 (reference): verify mismatch returns 1; cmov with b=1 moves the whole byte"
"$W/tool-ref128" ct

echo
echo "########################################################################"
echo "# [3] plaintext-checking oracle (optimized FLIT128): on each accepted"
echo "#     invalid ct', decapsulation == KDF(G(m'||H(pk))||H(ct')) recomputed"
echo "#     from public data; correct m' matches, wrong m' does not"
echo "########################################################################"
"$W/tool-opt128" pco 5
} 2>&1 | tee "$OUT/run.txt"

echo
echo "wrote $OUT/run.txt"
