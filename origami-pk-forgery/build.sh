#!/usr/bin/env bash
# Build the Origami public-key-only forger for one level against the reference
# implementation. The forger is appended to the unmodified reference origami_ref.c
# (it needs the reference's internal zone layout and public-map streamer), then
# linked with forge_main.c and the reference support objects.
#
#   ./build.sh "/path/to/Reference_Implementation/Origami-128"
#
# The reference implementation is NOT bundled and is not modified on disk.
set -e
REF="$1"; CC="${CC:-gcc-11}"
[ -d "$REF" ] || { echo "usage: ./build.sh <Reference_Implementation/Origami-LEVEL dir>"; exit 1; }
cat "$REF/origami_ref.c" src/forge_append.c > forge_lib.c   # ref map + appended pk-only forger
$CC -O2 -I"$REF" forge_lib.c src/forge_main.c \
    "$REF/auxfunc.c" "$REF/drng.c" "$REF/aes.c" \
    "$REF/symmetric_iccs.c" "$REF/SIG_AlgorithmInstance.c" -o forge
echo "built ./forge for $REF"
