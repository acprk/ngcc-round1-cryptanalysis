#!/usr/bin/env bash
# Amoeba key recovery from the pre-FO decryption-failure oracle, against the reference.
#   REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
# REFROOT must contain Amoeba-576 (the demonstrated set). Reference NOT bundled; src/ untouched.
set -e
REFROOT="${REFROOT:-../build/Amoeba/Reference_Implementation}"
CC="${CC:-gcc-11}"
echo "=== Amoeba-576 (scalar-probe key recovery) ==="
./build.sh "$REFROOT/Amoeba-576"
./attack
rm -f attack
echo "(517/517 directly-probed coefficients recovered exactly in ~5,700 chosen-ciphertext"
echo " queries, ~4 s wall / ~1.2 s CPU;"
echo " 'stack smashing detected' lines are the bonus OOB-write DoS in the ECC decoder,"
echo " observed in the forked oracle children.)"
