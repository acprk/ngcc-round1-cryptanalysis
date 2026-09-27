#!/usr/bin/env bash
# Build the Tins one-signature key-recovery / forgery against the reference
# implementation for one level.
#   ./build.sh "/path/to/Reference_Implementation/Tins256"
# The reference implementation is NOT bundled and is not modified on disk. The
# attacker links against the reference sign/verify and support objects only.
set -e
REF="$1"; CC="${CC:-gcc-11}"
[ -d "$REF" ] || { echo "usage: ./build.sh <Reference_Implementation/Tins{128,256,512} dir>"; exit 1; }
base=$(basename "$REF")
case "$base" in
  *128*) HDR='"SIG_TINS128.h"'; EXTRA="" ;;
  *512*) HDR='"SIG_TINS512.h"'; EXTRA="-DTINS512" ;;
  *)     HDR='"SIG_TINS256.h"'; EXTRA="" ;;
esac
SIGC=$(ls "$REF"/SIG_TINS*.c | head -1)
$CC -O3 -fopenmp -I"$REF" -DSIG_HDR="$HDR" $EXTRA \
    src/attack.c "$SIGC" "$REF/ff_arith.c" "$REF/drng.c" "$REF/bavc_commit.c" "$REF/auxfunc.c" \
    -o attack
echo "built ./attack for $REF"
