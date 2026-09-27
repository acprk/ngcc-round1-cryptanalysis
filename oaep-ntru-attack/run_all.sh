#!/usr/bin/env bash
# Reproduce the Coset-Lift Malleability attack and the Rejection Key-Leak probe
# on all three OAEP-NTRU parameter sets.
#
#   REFROOT=/path/to/Reference_Implementation ./run_all.sh
#
# REFROOT must contain OAEP-NTRU-648 / OAEP-NTRU-1296 / OAEP-NTRU-2592 source
# directories. These are black-box functional attacks (no timing), so no core
# pinning is needed.
set -e
REFROOT="${REFROOT:-./ref}"
N="${N:-1000}"

for n in 648 1296 2592; do
  REF="$REFROOT/OAEP-NTRU-$n"
  [ -d "$REF" ] || { echo "skip $n: $REF not found"; continue; }
  echo "================ OAEP-NTRU-$n ================"
  make -s clean
  make -s -j4 REF="$REF"
  ./coset_lift  "$N"
  ./reject_leak "$N"
done
