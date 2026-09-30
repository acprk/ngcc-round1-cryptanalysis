#!/usr/bin/env bash
# Reproduce the Weaver BCH-decoder / DFR findings against a vendor reference implementation.
#   REF=/path/to/Weaver/Implementations/Reference_Implementation ./run_all.sh [--dfr]
# REF must contain WeaverKEM-128, WeaverKEM-256, WeaverKEM-512 (submission package or GitHub
# Akutamatsu/weaverkem at ca99d0f, same layout). Nothing in $REF is modified: sets are copied to
# ./work/<variant>-<set> and patches are applied to the copies.
# Default run: ~2 min single core. --dfr additionally runs the exact DFR model (~15-20 min per set,
# single-threaded) and a small noise measurement (the full 3e8-coefficient measurement is
# `dfr/harness` with larger arguments, see README).
set -euo pipefail
: "${REF:?set REF to the Weaver Reference_Implementation directory}"
HERE=$(cd "$(dirname "$0")" && pwd)
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
SRCS="msgenc.c bch_high.c bch_low.c poly.c polyvec.c ntt.c reduce.c cbd.c symmetric-iccs.c auxfunc.c indcpa.c poly_invq.c drng.c"
mode() { case $1 in 128) echo 1;; 256) echo 3;; 512) echo 5;; esac; }
prep() { # $1 variant (orig|fixed|instr) $2 set
  local w=$HERE/work/$1-$2; rm -rf "$w"; mkdir -p "$HERE/work"; cp -r "$REF/WeaverKEM-$2" "$w"
  ( cd "$w" && sed -i 's/\r$//' *.c *.h )
  case $1 in  # same edits as patches/*.patch, applied with sed so one script fits every set
    fixed) sed -i 's/for (j = 1; j <=i+1 ; j++)/for (j = 1; j <= t \&\& j <= 2*i+2; j++)/' "$w/bch_high.c" "$w/bch_low.c"
           [ "$(grep -c 'j <= t && j <= 2\*i+2' "$w/bch_high.c" "$w/bch_low.c" | awk -F: '{s+=$2} END{print s}')" = 2 ] || { echo "BM patch did not apply" >&2; exit 1; } ;;
    instr) sed -i 's/^#include "symmetric.h"$/#include "symmetric.h"\npoly weaver_dbg_mp;/; s/^\( *\)poly_tomsg(m, &mp);/\1weaver_dbg_mp = mp;\n\1poly_tomsg(m, \&mp);/' "$w/indcpa.c"
           grep -q "weaver_dbg_mp = mp" "$w/indcpa.c" || { echo "instrumentation did not apply" >&2; exit 1; } ;;
  esac
  echo "$w"
}
cc() { gcc -O2 -w -DWEAVER_MODE=$(mode $2) -I"$3" "$1" $(for f in $SRCS; do echo "$3/$f"; done) -lm -o "$4"; }
mkdir -p "$HERE/out"
echo "== [1] direct BCH decoder test (data-bit errors, 20000 trials per weight), original vs fixed"
for k in 256 512; do for v in orig fixed; do w=$(prep $v $k); cc "$HERE/src/bch_direct.c" $k "$w" "$w/bch_direct"; echo "-- $v WeaverKEM-$k"; "$w/bch_direct"; done; done | tee "$HERE/out/bch_direct.txt"
echo "== [2] codec-level (poly_frommsg -> flip e high-layer payload coeffs -> poly_tomsg), original vs fixed"
for k in 256 512; do for v in orig fixed; do w=$HERE/work/$v-$k; cc "$HERE/src/codec_repro.c" $k "$w" "$w/codec"; echo "-- $v WeaverKEM-$k"; "$w/codec" 20000; done; done | tee "$HERE/out/codec_search.txt"
echo "== [3] minimal example (Weaver-1024, all-zero message, flip coeffs 32 61 143 209)"
Z=$(printf '00%.0s' $(seq 32))
for v in orig fixed; do echo "-- $v"; "$HERE/work/$v-256/codec" replay "$Z" 32 61 143 209; done | tee "$HERE/out/codec_replay.txt"
echo "== [4] one injected high-layer error through indcpa_enc/indcpa_dec (checks whether the high layer is decoded at all)"
for k in 128 256 512; do w=$(prep orig $k); cc "$HERE/src/flip1.c" $k "$w" "$w/flip1"; "$w/flip1"; done | tee "$HERE/out/flip1.txt"
echo "== [5] KAT with the BM fix vs the KAT produced by the unmodified code (must be identical)"
for k in 128 256 512; do for v in orig fixed; do w=$(prep $v $k)
  ( cd "$w" && gcc -O2 -w -DWEAVER_MODE=$(mode $k) -I. drng.c auxfunc.c KAT_KEM.c KEM_WeaverKEM-$k.c symmetric-iccs.c kem_cca.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c msgenc.c bch_high.c bch_low.c poly_invq.c -lm -o kat && ./kat >/dev/null 2>&1 )
  echo "WeaverKEM-$k $v $(sha256sum < "$(ls "$w"/output/*.txt | head -1)" | cut -c1-16)"; done; done | tee "$HERE/out/kat_sha256.txt"
if [[ "${1:-}" == "--dfr" ]]; then
  echo "== [6] exact DFR model (independence + conditional on ||s||,||r||) and failure-boosting table"
  mkdir -p "$HERE/out/dfr/logs"; cd "$HERE/out/dfr"
  for s in W640 W1024 W2048; do REF="$REF" python3 "$HERE/dfr/model.py" $s | tee logs/model_$s.log; done
  PYTHONPATH="$HERE/dfr" REF="$REF" python3 "$HERE/dfr/boost.py" W1024 | tee logs/boost_W1024.log
  echo "== [7] small noise measurement (validation of the model; full run: see README)"
  for k in 128 256 512; do w=$(prep instr $k); cc "$HERE/dfr/harness.c" $k "$w" "$w/harness"; "$w/harness" 20 200 1 "logs/w$k-small.txt"; head -3 "logs/w$k-small.txt"; done
fi
echo "done; outputs in $HERE/out"
