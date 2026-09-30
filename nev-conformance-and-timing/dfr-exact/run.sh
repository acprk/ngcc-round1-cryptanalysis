#!/usr/bin/env bash
# Exact decryption-failure-rate computation for all nine NEV distribution sets, both
# decoders (spec Noise2Pt and the submitted poly_tomsg). Pure Python + NumPy; no vendor
# code, no REF needed. Reproduces F-0 (C2 published DFR unattainable) and F-1 (submitted
# decoder is 0.07-0.44 bits BETTER than the specified one). ~1 core, a few minutes.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"; mkdir -p logs
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
echo "== [1] model A, all nine sets + self-check against six stored values (residual <= 0.0043 bits)"
python3 nev_dfr_decoders.py --model A --selfcheck | tee logs/modelA.log
echo "== [2] model B (exact e', worst-case message) + rigorous lower bound"
python3 nev_dfr_decoders.py --model B | tee logs/modelB.log
echo "== [3] summary: all four models x nine sets + the compressed C* rows -> results.json"
python3 summary.py | tee logs/summary.log
echo "== [4] verification suite V1-V4 (brute-force cross-check, float64 vs longdouble)"
python3 verify.py | tee logs/verify.log
echo "== [5] Monte-Carlo cross-check of the C2 pairing (5.12e7 samples, real ring arithmetic)"
python3 sim_c2.py | tee logs/sim_c2.log
echo
echo "Headlines:"
grep -E "C2 .*-20|SLOPE|F-1|shift" logs/summary.log 2>/dev/null | head
echo "  F-0: C2 exact DFR upper bound 2^-141.53, rigorous lower bound 2^-152.72,"
echo "       claim 2^-162 (Table 2) / 2^-173 (Table 7) is below the lower bound => unattainable."
echo "  F-1: submitted decoder DFR bound is 0.07-0.44 bits LOWER (better) than the spec decoder."
