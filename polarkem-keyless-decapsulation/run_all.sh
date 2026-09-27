#!/usr/bin/env bash
# Polar-KEM keyless-decapsulation attack: recover the shared secret from (pk, ct)
# alone, on the submitted KAT vectors, for all three parameter sets.
#
#   REFROOT=/path/to/Submission_Package ./run_all.sh
#
# REFROOT must contain Implementations/Reference_Implementation/PolarKEM-{128,256,512}
# and Test_Vectors/KAT_KEM_PolarKEM-{128,256,512}.txt. The reference implementation is
# NOT bundled and src/ is never modified.
set -e
REFROOT="${REFROOT:-../src/Polar-KEM/Submission_Package}"
RID="$REFROOT/Implementations/Reference_Implementation"
TV="$REFROOT/Test_Vectors"
CC="${CC:-gcc-11}"
for L in 128 256 512; do
  echo "=== PolarKEM-$L ==="
  make -s CC="$CC" REF="$RID/PolarKEM-$L" recover
  ./recover "$TV/KAT_KEM_PolarKEM-$L.txt"
  make -s clean
done
echo "done."
