#!/usr/bin/env bash
# Attribution helper for step 5: with the SUBMITTED key set and identical encapsulation
# coins, which single deviation changes the ciphertext? Run run_interop.sh first; it
# produces xfer/keys_sub_*.bin and xfer/enc_sub_sub_*.bin, which this script reuses.
#   REF=/path/.../Reference_Implementation/NEV-C1 ./run_isolate_encap.sh
set -u
WORK=""
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-/usr/bin/gcc}
X="$HERE/xfer"
[ -f "$X/keys_sub_1_ICCS.bin" ] || { echo "run run_interop.sh first (need xfer/keys_sub_*.bin)"; exit 1; }
WORK=$("$HERE/build_common.sh")
cp "$HERE/harness/xinterop.c" "$WORK/"
SOURCES="poly.c ntt.c owpke.c verify.c sample.c pack.c cca.c cpa.c"
SYM="symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c"
DR="kat_test/rng.c kat_test/drng.c"; INST="kat_test/KEM_AlgorithmInstance.c"
cd "$WORK"
jobs=0
for p in $(seq 1 12); do for be in ICCS SHA3; do for v in f1 f2 f3; do
  case $v in f1) D="-DSPEC_F1";; f2) D="-DSPEC_F2";; f3) D="-DSPEC_F3";; esac
  ( $CC -O2 -std=c99 -I. -Isymmetrics -Ikat_test -DPARAMS=$p -DUSE_$be $D \
      xinterop.c $SOURCES $SYM $DR $INST -o "$HERE/bin/xop_${v}_${p}_${be}" 2>/dev/null ) &
  jobs=$((jobs+1)); [ $((jobs % 8)) -eq 0 ] && wait
done; done; done
wait 2>/dev/null || true
{
echo "which deviation changes ENCAPSULATION? (submitted key set, identical coins)"
echo "ETA_R per set: 1,2,3=none(COMPRESS) 4=3 5=2 6=9 7=7 8=4 9=2 10,11,12=9"
for p in $(seq 1 12); do for be in ICCS SHA3; do
  line="PARAMS=$p $be  ct(vs submitted encap):"
  for v in f1 f2 f3; do
    "$HERE/bin/xop_${v}_${p}_${be}" encap "$X/keys_sub_${p}_${be}.bin" "$X/enc_sub_${v}_${p}_${be}.bin" >/dev/null
    if cmp -s "$X/enc_sub_sub_${p}_${be}.bin" "$X/enc_sub_${v}_${p}_${be}.bin"; then r=same; else r=DIFF; fi
    line="$line  $v=$r"
  done
  echo "$line"
done; done
} | tee "$HERE/logs/isolate_encap.txt"
