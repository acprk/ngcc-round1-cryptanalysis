#!/usr/bin/env bash
# Reproduce the TSUOV implementation findings against the submitted NICCS package.
# Usage: REF=/path/to/TSUOV ./run_all.sh     (REF = unzipped TSUOV.zip root, containing Implementations/)
# Builds into ./work/, never modifies anything under $REF.
set -u
: "${REF:?set REF to the unzipped TSUOV.zip root}"
HERE=$(cd "$(dirname "$0")" && pwd); W=$HERE/work; L=$HERE/logs; mkdir -p "$W" "$L"
RT="$REF/Implementations/Digital_Signature-TSUOV-x86-Reference_Implementation/API_PKC/Implementations/Reference_Implementation"
OT="$REF/Implementations/Digital_Signature-TSUOV-x86-Performance_Optimized_Implementation/API_PKC/Implementations/Optimized_Implementation"
CC=${CC:-$(command -v gcc-11 || echo gcc)}
ROPT="-std=c99 -O2 -D_GNU_SOURCE"; OOPT="-std=c99 -O3 -march=x86-64 -mavx2 -D_GNU_SOURCE"   # flags of the submitted Makefile / CMakeLists
declare -A SEED=([128]=16 [256]=32 [512]=64)
for lv in 128 256 512; do for t in Ref Opt; do
  if [ $t = Ref ]; then S=$RT/TSUOV_$lv; F=$ROPT; else S=$OT/TSUOV_$lv; F=$OOPT; fi
  d=$W/${t}_$lv; rm -rf "$d"; mkdir -p "$d"; cp "$S"/*.c "$S"/*.h "$d"/; rm -f "$d"/KAT_SIG.c
  B=$((8*${SEED[$lv]})); D="-DTSUOV_VARIANT=$lv -DSIG_SALT_BITS=$B -DPK_SEED_BITS=$B -I$d"
  for h in probe failopen failopen_rl failopen_sign; do $CC $F $D -o "$d/$h" "$HERE/src/$h.c" "$d"/*.c -lm 2>>"$L/build.log" || echo "build fail $t $lv $h"; done
  AF="-std=c99 -O1 -g -fsanitize=address -fno-omit-frame-pointer -D_GNU_SOURCE"; [ $t = Opt ] && AF="$AF -mavx2"
  $CC $AF $D -o "$d/asan2" "$HERE/src/asan2.c" "$d"/*.c -lm 2>>"$L/build.log" || echo "build fail $t $lv asan2"
done; done
for lv in 128 256 512; do for t in Ref Opt; do d=$W/${t}_$lv
  echo "===== $t-$lv"
  (cd "$d" && ./probe gen $t)                   > "$L/${t}_${lv}_probe.log" 2>&1
  (cd "$d" && ./failopen)                       > "$L/${t}_${lv}_failopen.log" 2>&1
  (cd "$d" && ./failopen_rl)                    > "$L/${t}_${lv}_failopen_rl.log" 2>&1
  (cd "$d" && ./failopen_sign)                  > "$L/${t}_${lv}_failopen_sign.log" 2>&1
  for m in 1 2 3; do (cd "$d" && ASAN_OPTIONS=detect_leaks=0 ./asan2 $m) > "$L/${t}_${lv}_asan$m.log" 2>&1; done
  grep -h "RLIMIT" "$L/${t}_${lv}_failopen_rl.log"
done; done
echo "== cross-verify (ref verifies opt output and vice versa)"
for lv in 128 256 512; do
  cp "$W"/Opt_$lv/Opt_*.bin "$W"/Ref_$lv/ 2>/dev/null; cp "$W"/Ref_$lv/Ref_*.bin "$W"/Opt_$lv/ 2>/dev/null
  (cd "$W/Ref_$lv" && ./probe verify Opt); (cd "$W/Opt_$lv" && ./probe verify Ref)
done | tee "$L/crossverify.log"
echo "== ASan summaries"; grep -h -E "ERROR: AddressSanitizer|SUMMARY" "$L"/*_asan*.log | sort | uniq -c
