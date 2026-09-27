#!/usr/bin/env bash
# Reproduce the Aigis-Enc+ decryption-oracle attack on all three parameter sets.
#
#   REFROOT=/path/to/Reference_Implementation ./run_all.sh
#
# REFROOT must contain Aigis-Enc+-I / Aigis-Enc+-II / Aigis-Enc+-III source dirs.
# The attack is a black-box CCA query attack; no pinning or timing is needed.
set -e
REFROOT="${REFROOT:-./ref}"
TRIALS="${TRIALS:-300}"
declare -A PSET=( [I]=1 [II]=2 [III]=3 )

for LVL in I II III; do
  REF="$REFROOT/Aigis-Enc+-$LVL"
  [ -d "$REF" ] || { echo "skip $LVL: $REF not found"; continue; }
  echo "================ Aigis-Enc+-$LVL (PARAMS=${PSET[$LVL]}) ================"
  make -s clean
  make -s -j4 PARAMS="${PSET[$LVL]}" REF="$REF"
  ./oracle  "$TRIALS"
  ./recover "$TRIALS"
done
