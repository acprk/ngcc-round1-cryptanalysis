#!/usr/bin/env bash
# HARE (ICCS NGCC round-1, kem-16) -- same-key multi-instance decoding (DS-DOOM, ePrint 2026/517).
#
#   REFROOT=/path/to/HARE_Code_Package ./run_all.sh
#
# REFROOT = the unmodified vendor package root (contains Implementations/ and Test_Vectors/).
# The vendor code is NEVER modified and NEVER redistributed: src/e2e.c is compiled together with the
# vendor sources in place.  The estimator doom.py is fetched from its public repository at a pinned
# commit (not redistributed either).
#
#   [kat] vendor KATs replay byte-for-byte with our build (sanity of the build line)
#   [cal] official doom.py reproduces ngcc.dev kem-05-2 (BIKE-MLThre) exactly
#   [est] HARE DS-DOOM cost vs number of same-key ciphertexts Q, all shipped sets (+ spec-only HARE-1/3)
#   [e2e] on the real implementation: ciphertext -> SD instance, rotations, decoder output -> session key
set -e -o pipefail
REFROOT="${REFROOT:?set REFROOT=/path/to/HARE package root}"
CC="${CC:-gcc}"; PY="${PY:-python3}"; TRIALS="${TRIALS:-20}"
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/src"; W="$HERE/work"; mkdir -p "$W"
R="$REFROOT/Implementations"; C="$R/_shared/hare_core"; A="$R/_shared/api_pkc"
DOOM_REPO=https://github.com/Gabsadio/Multi-Instance-KEM; DOOM_COMMIT=39b78dcc077793cfa3ccdce8d032ece76825ca55

if [ ! -f "$W/mi/doom.py" ]; then
  git clone -q "$DOOM_REPO" "$W/mi" && git -C "$W/mi" checkout -q "$DOOM_COMMIT"
fi
echo "doom.py: $DOOM_REPO @ $(git -C "$W/mi" rev-parse HEAD)  sha256 $(sha256sum "$W/mi/doom.py" | cut -c1-16)"

build(){ # build <level> <main.c> <out> [extra defs]
  local L=$1; "$CC" -O2 -std=gnu11 -w -DHARE_SYMMETRIC_MODE_B -DHARE_BACKEND_KR=1 -DHARE_INSTANCE_NAME="\"HARE-$L-kr\"" \
    -I"$R/Reference_Implementation/HARE-$L/kr" -I"$C/common" -I"$C/ref" -I"$A" \
    "$2" "$C"/common/*.c "$C"/ref/*.c "$A/auxfunc.c" "$A/drng.c" \
    "$R/Reference_Implementation/HARE-$L/kr/KEM_AlgorithmInstance.c" -o "$3" -lcrypto; }

echo; echo "=== [kat] vendor KAT replay (vendor Self_Evaluation/tests/verify_kat_kem.c, unmodified) ==="
for L in 128 256 384 512; do
  build $L "$REFROOT/Self_Evaluation/tests/verify_kat_kem.c" "$W/verify_kat_$L"
  ( cd "$REFROOT" && "$W/verify_kat_$L" ) 2>&1 | tail -1 | sed 's/^/  /'
done

echo; echo "=== [cal] official doom.py vs ngcc.dev kem-05-2 ==="
( cd "$W/mi" && PYTHONPATH="$W/mi" OMP_NUM_THREADS=1 "$PY" "$SRC/calib_kem05_2.py" )

echo; echo "=== [est] HARE same-key DS-DOOM, official doom.py ==="
( cd "$W/mi" && PYTHONPATH="$W/mi" OMP_NUM_THREADS=1 "$PY" "$SRC/hare_dsdoom.py" "$R" 0,40,56,60,61,62,63,64,66,68,70,72,74,76,78,80 ) | sed 's/^/  /'

echo; echo "=== [e2e] real implementation: ciphertext -> SD instance -> (decoder output) -> session key, $TRIALS trials/set ==="
for L in 128 256 384 512; do
  build $L "$SRC/e2e.c" "$W/e2e_$L"
  echo -n "  HARE-$L: "; "$W/e2e_$L" "$TRIALS"
done
echo; echo "ALL CHECKS PASSED"
