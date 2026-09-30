#!/usr/bin/env bash
# UVW-KEM: overall decryption-failure rate and a failure-only reaction attack.
#
#   ./run_all.sh                                   # part A only (python: mpmath, numpy)
#   REFROOT=/path/to/Reference_Implementation ./run_all.sh     # + part B (C harness, ASan)
#   LONG=1 REFROOT=... ./run_all.sh                # + malformed-ciphertext run (minutes)
#
# REFROOT must contain UVW-KEM-128, UVW-KEM-256, UVW-KEM-512 from the ICCS submission package.
set -e
cd "$(dirname "$0")"
mkdir -p logs
echo "=== A1. exact DFR after A retries (Theorem 2 counting; A=1 reproduces the spec) ==="
python3 src/dfr.py | tee logs/dfr.txt
echo "=== A2. UVW-128 DFR vs retry bound ==="
python3 src/dfr_vs_A.py | tee logs/dfr_vs_A.txt
echo "=== A3. failure probability by number of hidden bad pairs t ==="
python3 src/boost.py | tee logs/boost.txt
echo "=== A4. heavy-hitter pair/ratio recovery from final failures only (UVW-128 size) ==="
python3 src/hh_sim.py 500 1000 2000 | tee logs/hh_sim.txt
[ -z "$REFROOT" ] && { echo "REFROOT not set: skipping part B"; exit 0; }
for L in 128 256 512; do
  make -s REF="$REFROOT/UVW-KEM-$L" OUT=test_uvw_$L
  echo "=== B1. UVW-KEM-$L: one honest encaps/decaps under ASan (leaks) ==="
  ASAN_OPTIONS=detect_leaks=1 ./test_uvw_${L}_asan 0 2>&1 | grep -E 'dec ret|Direct leak|SUMMARY' | tee logs/leak_$L.txt || true
  echo "=== B2. UVW-KEM-$L: does a decapsulation advance the shared DRNG? ==="
  ./test_uvw_$L 2 | tee logs/drng_$L.txt
done
if [ -n "$LONG" ]; then
  echo "=== B3. UVW-KEM-128: 1-byte-modified c1 (runs the 1000-retry path) ==="
  ./test_uvw_128 4 3 | tee logs/malformed_128.txt
  echo "=== B4. UVW-KEM-256: same, RSS after 240 s ==="
  ( /usr/bin/time -v timeout 240 ./test_uvw_256 4 3 ) 2>&1 | grep -E 'Maximum resident|Elapsed' | tee logs/malformed_256_rss.txt || true
fi
echo done.
