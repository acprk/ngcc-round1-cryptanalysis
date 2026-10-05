#!/bin/bash
# Build the measurement harness against the BAG-Loong reference implementation.
#
#   REF=/path/to/BAG-Loong/Implementations/Reference_Implementation ./build.sh [VARIANT]
#
# VARIANT=B        (default) spec-conforming sampler: secret random supports,
#                  1 in Supp(Y), and Supp(E) = Supp(R2)
# VARIANT=A        sampler only (supports randomised, 1 in Supp(Y)); E left on Supp(R1)
# VARIANT=control  the archived code, unmodified
#
# The vendor reference implementation is NOT part of this repository; obtain it
# from the ICCS NGCC round-1 submission package.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
VARIANT=${1:-B}
: "${REF:?set REF=/path/to/BAG-Loong/Implementations/Reference_Implementation}"
[ -d "$REF/Loong-Block-ms-128" ] || {
  echo "REF=$REF does not contain Loong-Block-ms-128" >&2
  exit 1
}

OUT=$HERE/build/$VARIANT
rm -rf "$OUT"
mkdir -p "$OUT"
if [ "$VARIANT" = control ]; then
  for s in 128 256 384 512; do cp -r "$REF/Loong-Block-ms-$s" "$OUT/$s"; done
else
  python3 "$HERE/src/patch_sampler.py" "$REF" "$OUT" "$VARIANT"
fi

for s in 128 256 384 512; do
  D=$OUT/$s
  RBC=$(ls -d "$D"/lib/rbc-*)
  gcc -std=c99 -O2 -Wall -Wno-unused-function \
    -I"$D/src" -I"$D/lib/api_pkc" -I"$RBC" \
    "$HERE/src/instr.c" \
    "$D/src/augabidulin.c" "$D/src/ct_util.c" "$D/src/gabidulin.c" \
    "$D/src/loong_api_random.c" "$D/src/loong_hash.c" "$D/src/loong_kem.c" \
    "$D/src/loong_support.c" "$D/src/loong_xof_reader.c" "$D/src/parsing.c" \
    "$D/src/qpoly.c" "$RBC/rbc_elt.c" "$RBC/rbc_vec.c" \
    "$D/lib/api_pkc/auxfunc.c" "$D/lib/api_pkc/drng.c" \
    -o "$HERE/build/instr-$VARIANT-$s"
  echo "built build/instr-$VARIANT-$s"
done
