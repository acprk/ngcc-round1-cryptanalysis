#!/usr/bin/env bash
# Ciphertext-malleability audit of BRA and BRQC: an exhaustive single-bit-flip scan of
# each ciphertext, counting flips that decapsulate to the SAME shared secret. The padding
# bits of the last byte of u and of v are the equivalent encodings that break IND-CCA2.
#
#   REFROOT_BRA=/path/to/BRA/Implementations/Reference_Implementation \
#   REFROOT_BRQC=/path/to/BRQC/Implementations/Reference_Implementation ./run_all.sh
#
# The reference implementations are NOT bundled and are not modified (build.sh copies each
# to a scratch dir). Defaults reuse the known-good in-tree reference copies.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
REFROOT_BRA="${REFROOT_BRA:-$HERE/../build/BRA/Reference_Implementation}"
REFROOT_BRQC="${REFROOT_BRQC:-$HERE/../build/BRQC/Reference_Implementation}"

audit_one() { # <ref level dir> <header> <label>
  echo "=== $3 ==="
  "$HERE/build.sh" "$1" "$2" >/dev/null
  "$HERE/audit" 5 -1 30    # 5 roundtrips, full single-bit scan, 30 random-ct trials
}

for L in 128 256 512; do
  audit_one "$REFROOT_BRA/BRA-$L"   "KEM_BRA-$L.h"   "BRA-$L"
done
for L in 128 256 512; do
  audit_one "$REFROOT_BRQC/BRQC-$L" "KEM_BRQC-$L.h" "BRQC-$L"
done
echo "done. 'same_key' counts the equivalent (padding) ciphertext encodings; each is a"
echo "distinct byte string decapsulating to the identical shared secret (one-query CCA)."
