#!/usr/bin/env bash
# Reproduce the Shuttle key-recovery attack on all three parameter sets.
#
#   REFROOT=/path/to/Reference_Implementation ./run_all.sh
#
# REFROOT must contain SHUTTLE-128 / SHUTTLE-256 / SHUTTLE-512 source dirs.
# Pin to an idle core for stable timing; measurement is not required for the
# attack itself (it is a black-box query attack), only for the wall-clock line.
set -e
REFROOT="${REFROOT:-./ref}"
CORE="${CORE:-0}"
declare -A SIGS=( [128]=300000 [256]=600000 [512]=600000 )

for MODE in 128 256 512; do
  REF="$REFROOT/SHUTTLE-$MODE"
  [ -d "$REF" ] || { echo "skip $MODE: $REF not found"; continue; }
  echo "================ SHUTTLE-$MODE ================"
  make -s clean
  make -s MODE="$MODE" REF="$REF"
  echo "--- leakage probe (second-moment gap = kappa) ---"
  taskset -c "$CORE" ./leak_probe 20000 0 | grep -E "E\[|\|\|s"
  echo "--- full key recovery + forgery ---"
  taskset -c "$CORE" ./key_recovery "${SIGS[$MODE]}" 3
done
