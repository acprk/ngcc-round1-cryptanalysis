#!/usr/bin/env bash
# Origami public-key-only universal forgery on all four parameter sets, verified
# by the unmodified reference verifier.
#
#   REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
#
# REFROOT must contain Origami-{128,256,384,512}. The reference implementation is
# NOT bundled; src/ is never modified (the forger is appended to a COPY of origami_ref.c).
set -e
REFROOT="${REFROOT:-../src/Origami/Implementations and Test_Vectors/Implementations/Reference_Implementation}"
N="${N:-10}"
for L in 128 256 384 512; do
  echo "=== Origami-$L ==="
  ./build.sh "$REFROOT/Origami-$L"
  ./forge "$N" | tail -1
done
echo "done. (a produced forgery always has verify=0; a shortfall below N is the"
echo " forger's tail-zone linear-system restart, not a rejected signature.)"
