#!/usr/bin/env bash
# FlexTree sEUF-CMA strong forgery on all 8 parameter sets, Reference and Optimized,
# checked by the unmodified vendor crypto_sign_open.
#   IMPLROOT="/path/to/FlexTree/Implementations" ./run_all.sh
# IMPLROOT must contain Reference_Implementation/ and Optimized_Implementation/.
set -e
IMPLROOT="${IMPLROOT:?set IMPLROOT to the FlexTree Implementations directory}"
N="${N:-10}"
IMPLS="${IMPLS:-Reference_Implementation Optimized_Implementation}"
SETS="${SETS:-160s 160f 256s 256f 384s 384f 512s 512f}"
rc=0
for I in $IMPLS; do for S in $SETS; do
  D="$IMPLROOT/$I/Flextree-$S"; [ -d "$D" ] || { echo "skip Flextree-$S [$I] (not found)"; continue; }
  echo "=== Flextree-$S [$I] ==="
  ./build.sh "$D" ./poc >/dev/null
  ./poc "$N" "Flextree-$S[${I%%_*}]" | tail -1 || rc=1
done; done
rm -f ./poc
exit $rc
