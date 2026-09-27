#!/usr/bin/env bash
# LoongKEM sub-ring projection: dump a real Loong128 public key from the reference,
# apply psi to R_4, and verify the ring-hom identity + report the projected MLWE instance.
# Decision / IND-CPA break; the secret is dumped only to score the projection.
#   REF=/path/to/Reference_Implementation/Loong128 ./run_all.sh
# The reference implementation is NOT bundled; src/ is never modified.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
REF="${REF:-../build/LoongKEM/Implementations/Reference_Implementation/Loong128}"
CC="${CC:-gcc-11}"; PY="${PY:-sage -python}"
LATTICE_ESTIMATOR="${LATTICE_ESTIMATOR:-$HOME/xzy/lattice-estimator}"
mkdir -p "$HERE/logs"

echo "=== (1) build the key-dump harness against the reference ==="
if [ -d "$REF" ]; then
  $CC -O2 -I"$REF" src/dump_loong.c "$REF"/KEM_Loong.c "$REF"/poly.c "$REF"/auxfunc.c "$REF"/drng.c -o dump_loong
  echo "=== dump a real Loong128 key (harness writes dump.txt; # lines are self-tests on stdout) ==="
  ./dump_loong 1 dump.txt
  DUMP=dump.txt
else
  echo "(no REF LoongKEM Reference_Implementation/Loong128 dir; using bundled real-key dump)"
  DUMP="$([ -f dump.txt ] && echo dump.txt || echo src/sample_dump.txt)"
fi

echo "=== (2) projection-identity check on the real key -> logs/projection_identity.log ==="
$PY src/project_loong.py "$DUMP" | tee logs/projection_identity.log

echo "=== (3) lattice-estimator cost of the projected instances -> logs/estimate_loong.log ==="
LATTICE_ESTIMATOR="$LATTICE_ESTIMATOR" PYTHONPATH="$LATTICE_ESTIMATOR" \
  $PY src/estimate_loong.py | tee logs/estimate_loong.log

echo "=== (4) reduced-scale EXACT recoveries (dim 40, 55) -> logs/recover_dim{40,55}.log ==="
if command -v /usr/bin/time >/dev/null 2>&1; then TIME="/usr/bin/time -v"; else TIME=""; fi
$TIME $PY src/recover_reduced.py 40 2>&1 | tee logs/recover_dim40.log
$TIME $PY src/recover_reduced.py 55 2>&1 | tee logs/recover_dim55.log

echo "=== done; logs in logs/ ==="
