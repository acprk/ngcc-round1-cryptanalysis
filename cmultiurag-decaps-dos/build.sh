#!/usr/bin/env bash
# Build the C-Multi-UR-AG decapsulation-DoS auditor for one level against the reference
# implementation. Copies the reference level (never edits src/), runs the reference's own
# KAT target to compile its objects, then links the generic single-bit ct auditor against them.
#
#   ./build.sh "/path/to/Reference_Implementation/CMultiURAG-256" 256
#
# The reference implementation is NOT bundled and is not modified on disk.
set -e
REF="$1"; L="$2"; CC="${CC:-gcc-11}"
[ -d "$REF" ] || { echo "usage: ./build.sh <Reference_Implementation/CMultiURAG-LEVEL dir> <128|256|512>"; exit 1; }
rm -rf refcopy && cp -r "$REF" refcopy
( cd refcopy && make -s "CMultiURAG-$L-kat" >/dev/null 2>&1 || make -s "CMultiURAG-$L-kat" )
$CC -std=c99 -O2 -no-pie -I refcopy -I refcopy/src -I refcopy/src/rbc-127 \
    -I refcopy/lib/random_source -I refcopy/lib/XKCP -I refcopy/lib/XKCP/opt64 -I refcopy/lib/wrapper \
    -DHDR="\"KEM_CMultiURAG-$L.h\"" src/kem_audit.c refcopy/bin/build/*.o -o audit
echo "built ./audit for CMultiURAG-$L"
