#!/usr/bin/env bash
# MAMBA-NIKE static secret-key recovery against the reference implementation, via a
# key-mismatch / reaction oracle on the reused static responder key.
#
#   REFROOT="/path/to/Implementations/Reference_Implementation" NKEYS=30 ./run_all.sh
#
# REFROOT must contain MAMBA-NIKE-128 and MAMBA-NIKE-384. The reference implementation is
# NOT bundled and src/ is never modified; the oracle is the reference's own
# -DSTATISTICAL_TEST reconciliation output.
set -e
REFROOT="${REFROOT:-../src/MAMBA-NIKE/Implementations/Reference_Implementation}"
NKEYS="${NKEYS:-30}"
CC="${CC:-gcc-11}"

echo "=== MAMBA-NIKE-128 (n=1024, eta=2) ==="
make -s CC="$CC" REF="$REFROOT/MAMBA-NIKE-128" attack
./attack "$NKEYS"
make -s clean

echo "=== MAMBA-NIKE-384 (n=2048, eta=2) ==="
make -s CC="$CC" REF="$REFROOT/MAMBA-NIKE-384" attackgen
./attackgen 5
make -s clean
echo "done."
