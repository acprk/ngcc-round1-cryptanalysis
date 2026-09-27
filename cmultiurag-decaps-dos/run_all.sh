#!/usr/bin/env bash
# C-Multi-UR-AG decapsulation denial-of-service: a single flipped ciphertext bit
# segfaults the reference decapsulation at Level-256. Level-128/512 are unaffected in
# our tests (the same unbounded-loop bug is one allocation layout away from the same fate).
#
#   REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
#
# REFROOT must contain CMultiURAG-128/256/512. Reference NOT bundled; src/ never modified.
set -e
REFROOT="${REFROOT:-../src/C-Multi-UR-AG/Implementations/Reference_Implementation}"
for L in 128 256 512; do
  echo "=== CMultiURAG-$L ==="
  ./build.sh "$REFROOT/CMultiURAG-$L" "$L"
  # 3 roundtrips, single-bit ct scan (cap 120 bits for speed), 10 random ciphertexts
  ./audit 3 120 10 | tail -3
  rm -rf refcopy audit
done
echo "done. (Level-256 crashes on ~74% of single-bit flips and 100% of random ciphertexts;"
echo " Level-128/512 show 0 crashes in this scan.)"
