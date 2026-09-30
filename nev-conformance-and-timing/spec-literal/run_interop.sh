#!/usr/bin/env bash
# Step 5: cross encapsulation / decapsulation between the submitted code (`sub`, no
# -DSPEC_*) and the spec-literal implementation (`spl`, F1+F2+F3), 12 sets x 2 backends
# x 2 directions x N key pairs, plus the two same-implementation controls. Both binaries
# are built from the SAME patched work tree, so any disagreement is attributable to the
# three switches and to nothing else (compiler, libc and ABI are shared).
#   REF=/path/.../Reference_Implementation/NEV-C1 ./run_interop.sh [N]
set -u
WORK=""
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-/usr/bin/gcc}
N=${1:-200}
WORK=$("$HERE/build_common.sh")
CFLAGS="-O2 -fomit-frame-pointer -std=c99"
INC="-I. -Isymmetrics -Ikat_test"
SOURCES="poly.c ntt.c owpke.c verify.c sample.c pack.c cca.c cpa.c"
SYM="symmetrics/hashkdf.c symmetrics/fips202.c symmetrics/auxfunc.c"
DR="kat_test/rng.c kat_test/drng.c"
INST="kat_test/KEM_AlgorithmInstance.c"
LOG="$HERE/logs"; mkdir -p "$LOG" "$HERE/bin" "$HERE/xfer"
cp "$HERE/harness/xinterop.c" "$WORK/"
cd "$WORK"
jobs=0
for p in $(seq 1 12); do for be in ICCS SHA3; do for v in sub spl; do
  [ "$v" = spl ] && D="-DSPEC_F1 -DSPEC_F2 -DSPEC_F3" || D=""
  ( $CC $CFLAGS $INC -DPARAMS=$p -DUSE_$be $D xinterop.c $SOURCES $SYM $DR $INST \
      -o "$HERE/bin/xop_${v}_${p}_${be}" > "$LOG/xbuild_${v}_${p}_${be}.log" 2>&1 \
    || echo "BUILD-FAIL $v $p $be" ) &
  jobs=$((jobs+1)); [ $((jobs % 8)) -eq 0 ] && wait
done; done; done
wait
echo "built $(ls "$HERE"/bin/xop_* | wc -l) / 48 interop binaries"; echo
X="$HERE/xfer"
{
for p in $(seq 1 12); do for be in ICCS SHA3; do
  S="$HERE/bin/xop_sub_${p}_${be}"; L="$HERE/bin/xop_spl_${p}_${be}"
  "$S" keys "$N" "$X/keys_sub_${p}_${be}.bin" > /dev/null || { echo "KEYFAIL sub $p $be"; continue; }
  "$L" keys "$N" "$X/keys_spl_${p}_${be}.bin" > /dev/null || { echo "KEYFAIL spl $p $be"; continue; }
  if cmp -s "$X/keys_sub_${p}_${be}.bin" "$X/keys_spl_${p}_${be}.bin"; then kq=KEYS-IDENTICAL; else kq=KEYS-DIFFER; fi
  for kv in sub spl; do for ev in sub spl; do
    B="$HERE/bin/xop_${ev}_${p}_${be}"
    "$B" encap "$X/keys_${kv}_${p}_${be}.bin" "$X/enc_${kv}_${ev}_${p}_${be}.bin" > /dev/null \
      || echo "ENCFAIL k=$kv e=$ev $p $be"
  done; done
  if cmp -s "$X/enc_sub_sub_${p}_${be}.bin" "$X/enc_sub_spl_${p}_${be}.bin"; then cq=CT-IDENTICAL; else cq=CT-DIFFER; fi
  echo "== PARAMS=$p $be  $kq  (same pk, both encapsulators) $cq"
  for kv in sub spl; do for ev in sub spl; do
    D="$HERE/bin/xop_${kv}_${p}_${be}"
    out=$("$D" decap "$X/keys_${kv}_${p}_${be}.bin" "$X/enc_${kv}_${ev}_${p}_${be}.bin"); rc=$?
    lab="keys+decap=$kv encap=$ev"; [ "$kv" = "$ev" ] && lab="$lab [control]" || lab="$lab [CROSS]"
    echo "   $lab rc=$rc  $out"
  done; done
done; done
} | tee "$LOG/interop.txt"
