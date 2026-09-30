#!/usr/bin/env bash
# Build the DR0 oracle used by the fixed-point scripts.
#   ./build.sh                 self-contained oracle (modes: kbar | dr0 | fp | dr0k | bench)
#   REF=<vendor ref dir> ./build.sh   additionally links the vendor uBlock core and enables
#                              "./dr0_lib validate" (0/10000 mismatches expected)
set -euo pipefail
H="$(cd "$(dirname "$0")" && pwd)/fixedpoint"
cd "$H"
if [ -n "${REF:-}" ]; then
  V="$REF/ublockith_em_d3_256f"
  gcc -O2 -w -c -I"$V" -I"$V/utils_ublock" "$V/utils_ublock/ublock_core.c" -o ublock_core.o
  gcc -O2 -w -c -I"$V" "$V/utils.c" -o utils.o
  gcc -O2 -w -DHAVE_LIB -I"$V/utils_ublock" -I"$V" dr0_oracle.c ublock_core.o utils.o -o dr0_lib
  ./dr0_lib validate
else
  gcc -O2 -w dr0_oracle.c -o dr0_lib
  echo "built self-contained ./fixedpoint/dr0_lib (set REF= to cross-validate against the vendor core)"
fi
cp dr0_lib dr0_self
python3 dr0.py validate ./dr0_lib 0000000000000000000000000000000000000000000000000000000000000000 || true
