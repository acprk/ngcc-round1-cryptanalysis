#!/usr/bin/env bash
# NIIKE (NGCC round-1) verification package.
#
#   REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
#
# REFROOT must be the vendor NIIKE reference tree (contains NIIKE-lv128, -lv256,
# -lv512, protocols/, ec/, gf/, common/, ngccapi/). The reference implementation
# is NOT bundled and is never modified; we cmake-build it read-only into a temp
# dir, then (a) run the parameter/KAT verifier and (b) link the public-key
# validation probe against the built lv128 objects.
set -e

REFROOT="${REFROOT:-../src/NIIKE/Implementations and Test_Vectors/Implementations/Reference_Implementation}"
# Test_Vectors sits two levels up from Reference_Implementation in the vendor package
KATROOT="${KATROOT:-$REFROOT/../../Test_Vectors}"
CC="${CC:-gcc}"
HERE="$(cd "$(dirname "$0")" && pwd)"

if [ ! -d "$REFROOT" ]; then echo "REFROOT not found: $REFROOT" >&2; exit 1; fi

echo "=== 1. parameter / KAT verifier (items 2,3,6) ==="
REFROOT="$REFROOT" KATROOT="$KATROOT" python3 "$HERE/verify_niike.py"

echo
echo "=== 2. public-key validation probe (item 1), lv128 ==="
BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
# Build the vendor reference read-only (Release = the configuration a deployer ships).
cmake -S "$REFROOT" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
cmake --build "$BUILD" --target KAT_KEX_NIIKE-lv128 -j4 >/dev/null 2>&1

L=NIIKE-lv128
INC=(-I "$REFROOT/$L/ngccapi/include" -I "$REFROOT/$L/precomp/include"
     -I "$REFROOT/protocols/include" -I "$REFROOT/gf/include"
     -I "$REFROOT/ec/include" -I "$REFROOT/common/include"
     -I "$REFROOT/$L/gf/include")
# link every reference object except the one carrying the reference main()
OBJS=$(find "$BUILD/$L" -name '*.o' ! -name 'KAT_KEX.c.o' | tr '\n' ' ')
$CC -O2 "${INC[@]}" "$HERE/src/probe.c" $OBJS -o "$BUILD/probe"
"$BUILD/probe"

echo
echo "done."
