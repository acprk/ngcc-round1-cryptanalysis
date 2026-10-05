#!/bin/bash
# Reproduce every number in the BAG-Loong forum comment.
#
#   REF=/path/to/BAG-Loong/Implementations/Reference_Implementation ./run_all.sh
#
# Runtime: a few minutes for the harness, ~20 min for the reduced-scale recovery
# runs, ~5 min for the estimator (needs CryptographicEstimators; skipped if absent).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
: "${REF:?set REF=/path/to/BAG-Loong/Implementations/Reference_Implementation}"
PY=${PY:-python3}
mkdir -p "$HERE/out"

echo "=== build: spec-conforming sampler (variant B) and the archived control ==="
REF="$REF" bash "$HERE/build.sh" B
REF="$REF" bash "$HERE/build.sh" control

echo
echo "=== Section 1, experiment (a): merged rank on real keys (20 keys x 4 sets) ==="
for s in 128 256 384 512; do
  "$HERE/build/instr-B-$s" rank 20 0 7
done | tee "$HERE/out/rank.txt"

echo
echo "=== Section 2: KEM round-trips, conforming sampler vs archived code ==="
for s in 128 256 384 512; do
  "$HERE/build/instr-B-$s" kat 10 0 11 | tail -1
  "$HERE/build/instr-control-$s" kat 10 0 11 | tail -1
done | tee "$HERE/out/kat.txt"

echo
echo "=== Section 2: residual rank and tail support dimension (100 ct x 4 sets) ==="
for s in 128 256 384 512; do
  "$HERE/build/instr-B-$s" noise 10 10 101
  "$HERE/build/instr-control-$s" noise 10 10 101
done | tee "$HERE/out/noise.txt"

echo
echo "=== Section 1, experiment (b): reduced-scale full key recovery ==="
$PY "$HERE/src/merged_vs_block.py" 9 10 2 2 1 4 4 8 23 2000000 merged \
  | tee "$HERE/out/recover-m9.txt"
$PY "$HERE/src/merged_vs_block.py" 11 12 2 2 1 5 4 4 29 4000000 merged \
  | tee "$HERE/out/recover-m11.txt"

echo
echo "=== Section 1, experiment (c): merged vs per-block hit rates ==="
$PY "$HERE/src/merged_vs_block.py" prob 9 2 2 1 4 2000000 7 \
  | tee "$HERE/out/prob-A.txt"
$PY "$HERE/src/merged_vs_block.py" prob 9 2 2 2 4 2000000 41 \
  | tee "$HERE/out/prob-B.txt"

echo
echo "=== Section 1: closed-form AGHT ==="
$PY "$HERE/estimator/aght_closed_form.py" | tee "$HERE/out/aght.txt"

echo
echo "=== Section 1: CryptographicEstimators (both instances, three omegas) ==="
if $PY -c "import cryptographic_estimators" 2>/dev/null; then
  $PY "$HERE/estimator/estimate.py" | tee "$HERE/out/estimate.txt"
else
  echo "SKIPPED: pip install cryptographic-estimators (we used 2.1.1)"
fi

echo
echo "All outputs in $HERE/out/"
