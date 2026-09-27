#!/usr/bin/env bash
# UVW_signature: demonstrate that the shipped NGCC verifier accepts every signature.
#   REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
# REFROOT must contain UVW-128 (and optionally UVW-256/UVW-512). The reference
# implementation is NOT bundled and src/ is never modified.
set -e
REFROOT="${REFROOT:-../src/UVW_signature/Implementations/Reference_Implementation}"
CC="${CC:-gcc-11}"
LEVELS="${LEVELS:-UVW-128}"
for L in $LEVELS; do
  echo "=== $L ==="
  make -s CC="$CC" REF="$REFROOT/$L" apitamper
  ./apitamper
  make -s clean
done
echo "0=ACCEPT for honest AND tampered AND garbage AND wrong-message => verifier accepts everything."
