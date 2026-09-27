#!/usr/bin/env bash
# QIMEN-PIKE ciphertext-malleability + DoS demo on all three NGCC levels, against the
# unmodified reference decapsulation.
#   REF="/path/to/QIMEN-PIKE/Implementations/Implementations" ./run_all.sh
# The reference implementation is NOT bundled and is not modified (build.sh works on a copy).
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
REF="${REF:-$HERE/../src/QIMEN-PIKE/Implementations/Implementations}"
"$HERE/build.sh" "$REF"
for lv in 1 2 3; do
  echo "=== NGCC-$lv ==="
  "$HERE/malleability_demo_$lv"
done
echo "done. 'same shared secret' = a non-canonical ct (ct+p in an Fp slot, or a flipped"
echo "padding byte) that decapsulates to the challenge key (one-query CCA); 'CRASH' = a"
echo "negative-hint ciphertext that segfaults kem_dec (remote DoS)."
