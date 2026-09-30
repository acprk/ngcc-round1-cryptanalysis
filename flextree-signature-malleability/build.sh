#!/usr/bin/env bash
# Build the PoC against ONE vendor FlexTree directory (Reference or Optimized).
#   ./build.sh "/path/to/Reference_Implementation/Flextree-160s" [out_binary]
# The vendor directory is only read (copied to a temp dir); nothing is modified.
set -e
REF="$1"; OUT="${2:-./poc}"
[ -f "$REF/pors_fp.c" ] || { echo "not a FlexTree implementation dir: $REF" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT";; esac
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
cp -r "$REF"/. "$W"/
PARAMS="$(basename "$REF" | tr 'A-Z' 'a-z')"                         # e.g. flextree-160s
CFLAGS="-O3 -std=c99 -w -DPARAMS=$PARAMS"
if [ -f "$W/utils_avx2.c" ]; then                                     # Optimized_Implementation
  CFLAGS="$CFLAGS -march=native -mavx2 -DSPX_ENABLE_X8_WOTS -DSPX_ENABLE_X8_PORS"
fi
SRCS=$(cd "$W" && ls *.c | grep -v -x -e KAT_SIG.c -e pors_fp.c)
cp "$HERE/src/maul.c" "$HERE/src/poc_main.c" "$W"/
( cd "$W" && ${CC:-gcc} $CFLAGS -I. $SRCS maul.c poc_main.c -o "$OUT" -lm )
echo "built $OUT  (PARAMS=$PARAMS)"
