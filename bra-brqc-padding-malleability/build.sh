#!/usr/bin/env bash
# Build the ciphertext-malleability audit tool against one BRA/BRQC reference level.
#   ./build.sh <reference-impl level dir> <KEM header, e.g. KEM_BRA-128.h>
# The reference implementation is NOT modified: it is copied to a scratch dir, built
# there (producing bin/build/*.o), and the audit tool is linked against those objects.
set -e
REF="$1"; HDR="$2"
[ -d "$REF" ] || { echo "usage: ./build.sh <Reference_Implementation/SCHEME-LEVEL dir> <KEM_SCHEME-LEVEL.h>"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
cp -r "$REF"/. "$WORK"/
( cd "$WORK" && make -s >/dev/null 2>&1 || make >/dev/null 2>&1 )
gcc -O2 -std=gnu99 -DHDR="\"$HDR\"" "$HERE/src/kem_audit.c" "$WORK"/bin/build/*.o -I "$WORK" -o "$HERE/audit"
echo "built $HERE/audit against $REF"
