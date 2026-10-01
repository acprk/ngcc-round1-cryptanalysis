#!/usr/bin/env bash
# MAMBA-Frost (kem-20) specification review: (1) multi-ciphertext attack on the unsalted spec Alg. 7 (scaled),
# (2) public message check behind the Frost-128 Grover margin.
#   REFROOT=/path/to/API_PKC/Implementations/Reference_Implementation ./run_all.sh [salted]
# Nothing under $REFROOT is modified or copied; only randombytes() is supplied by us.
# (1) ~3 min single core; "salted" adds the 3-seed control (~27 min each). (2) a few seconds.
set -euo pipefail
: "${REFROOT:?set REFROOT to API_PKC/Implementations/Reference_Implementation}"
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$HERE/out; mkdir -p "$OUT"
CFL="-DNIX -D_AMD64_ -D_REFERENCE_ -D_AES128_FOR_A_ -DFROST_USE_E8_CODE -std=c99 -O2"
core() { local R=$REFROOT/MAMBA-Frost-$1; echo "$R/drng.c $R/auxfunc.c $R/Frost/src/frost$1.c $R/Frost/src/util.c $R/common/sha3/fips202.c $R/common/aes/aes_c.c"; }
ulimit -s unlimited 2>/dev/null || true

R=$REFROOT/MAMBA-Frost-128
cc $CFL -I"$R" "$HERE/src/multict.c" $(core 128) -o "$OUT/multict"
echo "== (1) spec Alg. 7 (unsalted): one guess of M tests all T ciphertexts"
for s in 1 2 3 4 5 6 7 8; do "$OUT/multict" $s; done | tee "$OUT/unsalted.log"
if [ "${1:-}" = salted ]; then
  echo "== (1) control: submitted code (fresh public salt per ciphertext)"
  for s in 1 2 3; do "$OUT/multict" $s salted; done | tee "$OUT/salted.log"
fi

echo "== (2) public check of a candidate M from (pk, ct): no sk, no decapsulation oracle"
for l in 128 256 512; do R=$REFROOT/MAMBA-Frost-$l
  cc $CFL -I"$R" -DAPI_H="\"Frost/src/api_frost$l.h\"" -DENC=crypto_kem_enc_Frost$l -DKEYPAIR=crypto_kem_keypair_Frost$l \
     -DNAME="\"Frost-$l\"" "$HERE/src/pubcheck.c" $(core $l) -o "$OUT/pubcheck$l"
  "$OUT/pubcheck$l"
done | tee "$OUT/pubcheck.log"
