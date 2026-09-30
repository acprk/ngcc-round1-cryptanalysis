#!/bin/bash
# SYDO (NGCC sign-28) — verification package for two findings:
#   F1  grinding parameters are self-contradictory; both implementations enforce only
#       wgrind-2 zero bits  =>  soundness lambda-2 for all six parameter sets
#   F2  the Reference implementation omits the spec-required zero check on the BAVC
#       opening padding  =>  signature malleability + ref/opt verdict divergence
#
# We do NOT redistribute the submitter's code. Point REF= at the SYDO submission tree
# (the directory containing Reference_Implementation/, Optimized_Implementation/,
#  Test_Vectors/).
#
#   REF=/path/to/SYDO ./run_all.sh              # F1 only (fast, no vendor build needed for step 1)
#   REF=/path/to/SYDO ./run_all.sh full         # F1 + F2 + a bounded bit-flip sweep
#
# Toolchain: Reference needs gcc >= 9 (-std=c11). Optimized needs clang >= 17
# (it hardcodes -std=c2x/-std=c++2b; gcc-12 fails on `static_assert(false)` in a
# template, C++ P2593). Set CC_OPT/CXX_OPT to override.
set -u

REF=${REF:?set REF=/path/to/SYDO submission tree}
MODE=${1:-fast}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$HERE/work}
CC_REF=${CC_REF:-gcc}
CC_OPT=${CC_OPT:-clang}
CXX_OPT=${CXX_OPT:-clang++}
SETS=${SETS:-"160s 160f 256s 256f 512s 512f"}

mkdir -p "$WORK" "$HERE/results"

# The submission nests the two trees under Implementations/; older repackagings put them
# at the top level, so accept both.
refdir() {
  for p in "$REF/Implementations/Reference_Implementation/sydo_$1" "$REF/Reference_Implementation/sydo_$1"; do
    [ -d "$p" ] && { echo "$p"; return; }
  done; echo "$REF/Implementations/Reference_Implementation/sydo_$1"
}
optdir() {
  for p in "$REF/Implementations/Optimized_Implementation/sydo_$1" "$REF/Optimized_Implementation/sydo_$1"; do
    [ -d "$p" ] && { echo "$p"; return; }
  done; echo "$REF/Implementations/Optimized_Implementation/sydo_$1"
}

# ---------------------------------------------------------------- build helpers
# Build the vendor tree in a scratch copy, then link our harness against the
# vendor object files. LAYOUT=1 also exposes the ref-only signature-layout probe.
build_one() {  # $1=impl(ref|opt) $2=set
  local impl=$1 lv=$2 src out cc cxx cppflags cflags
  out="$WORK/${impl}_$lv"
  [ -x "$out/xv" ] && [ -x "$out/sweep" ] && return 0
  if [ "$impl" = ref ]; then
    src=$(refdir "$lv"); cc=$CC_REF
    cppflags="-I. -Isrc -Ilib -Ilib/blake2/ref -DHAVE_SYS_RANDOM_H -DHAVE_GETRANDOM -DSYDO_REF_NGCC -DSYDO_REF_LAYOUT"
    cflags="-O3 -DNDEBUG -std=c11"
  else
    src=$(optdir "$lv"); cc=$CC_OPT; cxx=$CXX_OPT
    cppflags="-I. -Isrc -Ilib -Ilib/blake2/sse"
    cflags="-O3 -DNDEBUG -std=c2x -march=native -mtune=native"
  fi
  [ -d "$src" ] || { echo "MISSING $src"; return 1; }
  rm -rf "$out"; cp -r "$src" "$out" || return 1

  echo "[build] $impl $lv"
  # The Optimized Makefile hardcodes -std=c23 / -std=c++23 and gates the build on a
  # toolchain self-test for those exact spellings. clang-17 implements the same language
  # under the -std=c2x / -std=c++2b spellings and rejects c23/c++23, so an out-of-the-box
  # build fails on it. We rewrite the spelling in OUR scratch copy only (this is the same
  # adaptation noted in the comment as an engineering issue, not part of either finding).
  if [ "$impl" = opt ] && ! printf 'int main(void){return 0;}\n' | $cc -x c -std=c23 -c -o /dev/null - >/dev/null 2>&1; then
    echo "       (compiler rejects -std=c23; rewriting to -std=c2x/-std=c++2b in the scratch copy)"
    sed -i 's/-std=c23/-std=c2x/g; s/-std=c++23/-std=c++2b/g' "$out/Makefile"
  fi
  if [ "$impl" = ref ]; then
    ( cd "$out" && make CC="$cc" all >build.log 2>&1 ) || { echo "  vendor build FAILED (see $out/build.log)"; return 1; }
    OBJS=$(cd "$out" && ls SIG_AlgorithmInstance.o src/*.o lib/*.o lib/blake2/ref/*.o 2>/dev/null | tr '\n' ' ')
  else
    ( cd "$out" && make CC="$cc" CXX="$cxx" all >build.log 2>&1 ) || { echo "  vendor build FAILED (see $out/build.log)"; return 1; }
    OBJS=$(cd "$out" && ls SIG_AlgorithmInstance.o src/*.o src/*/*.o lib/*.o lib/blake2/sse/*.o 2>/dev/null | tr '\n' ' ')
  fi

  # Our harness. The Optimized tree has .cpp units and is built with -flto, so its object
  # files are LTO bitcode: link them with clang++ AND -flto or ld cannot read them.
  local LD=$cc LDEXTRA=""
  if [ "$impl" = opt ]; then LD=$cxx; LDEXTRA="-flto"; fi
  for tgt in xv sweep; do
    ( cd "$out" && $cc $cflags $cppflags -c "$HERE/src/$tgt.c" -o "$tgt.o" 2>>build.log ) || { echo "  harness $tgt compile FAILED"; return 1; }
    ( cd "$out" && $LD $LDEXTRA $tgt.o $OBJS -o "$tgt" 2>>build.log ) || { echo "  harness $tgt link FAILED (see $out/build.log)"; return 1; }
  done
  if [ "$impl" = ref ]; then
    ( cd "$out" && $cc $cflags $cppflags -c "$HERE/src/layout.c" -o layout.o 2>>build.log \
        && $cc $cflags layout.o $OBJS -o layout 2>>build.log ) || echo "  (layout probe unavailable)"
  fi
  return 0
}

# ============================================================ F1: grinding bits
echo "===================================================================="
echo " F1  grinding: spec wgrind vs. the number of zero bits actually enforced"
echo "===================================================================="
# (a) read delta_bits / enforced_zero_bits straight out of each built Reference binary
: > "$WORK/layouts.txt"
for lv in $SETS; do
  build_one ref "$lv" && "$WORK/ref_$lv/layout" >> "$WORK/layouts.txt"
done
if [ -s "$WORK/layouts.txt" ]; then
  cp "$WORK/layouts.txt" "$HERE/results/layouts.txt"
else
  echo "no layout output; falling back to the committed results/layouts.txt"
  cp "$HERE/results/layouts.txt" "$WORK/layouts.txt"
fi
cat "$WORK/layouts.txt"

# (b) do the SHIPPED KAT signatures satisfy the spec's own grinding condition?
echo; echo "--- official KAT vs spec grinding condition (Alg.3 line 7) ---"
REF="$REF" LAYOUTS="$WORK/layouts.txt" python3 "$HERE/tools/kat_grind.py" | tee "$HERE/results/kat_grind.log"

# (c) grinding-counter means vs the spec's own Table 5.5
echo; echo "--- KAT grinding counters vs spec Table 5.5 ---"
REF="$REF" LAYOUTS="$WORK/layouts.txt" python3 "$HERE/tools/kat_ctr.py" | tee "$HERE/results/kat_ctr.log"

# (d) scaled model: a degree-d QuickSilver check can be cheated on d self-chosen Deltas
echo; echo "--- scaled QuickSilver d-root cheating model ---"
python3 "$HERE/tools/qs_cheat.py" | tee "$HERE/results/qs_cheat.log"

[ "$MODE" = full ] || { echo; echo "F1 done. Re-run with 'full' for F2 and the bit-flip sweep."; exit 0; }

# ==================================================== F2: BAVC opening padding
echo; echo "===================================================================="
echo " F2  BAVC opening padding: Reference accepts, Optimized rejects"
echo "===================================================================="
LOG=$HERE/results/padding_crossverify.log
: > "$LOG"
for lv in $SETS; do
  build_one ref "$lv" || continue
  build_one opt "$lv" || continue
  for t in 0 1 2; do
    d=$WORK/runs/${lv}_t$t; mkdir -p "$d"
    { echo "== $lv trial $t"
      "$WORK/ref_$lv/xv" gen "$d" "$t"
      # measure the free (should-be-zero) tail of bavc_open, write sig_mut.bin
      "$WORK/ref_$lv/xv" pad "$d"
      echo -n "  opt: "; "$WORK/opt_$lv/xv" ver "$d" sig.bin | tr '\n' ' '
      "$WORK/opt_$lv/xv" ver "$d" sig_mut.bin
      echo -n "  ref: "; "$WORK/ref_$lv/xv" ver "$d" sig.bin | tr '\n' ' '
      "$WORK/ref_$lv/xv" ver "$d" sig_mut.bin
    } | tee -a "$LOG"
  done
done

# -------------------------------------- bounded sweep (negative control for opt)
echo; echo "--- bounded single-bit sweep: tail of a 160f signature from byte 6000 ---"
echo "    This window contains the whole padding run [6540,6680), so it reproduces the SAME"
echo "    accept count as an exhaustive sweep (1120 = 140 free bytes x 8) at 1/9 the cost."
echo "    Expect: ref accepts 1120, opt accepts 0."
d=$WORK/runs/160f_t0
for impl in ref opt; do
  echo -n "  $impl: "; "$WORK/${impl}_160f/sweep" "$d" sig.bin 6000 7000 | tail -1
done
echo
echo "Full-scale sweep numbers are in results/SWEEP-SUMMARY.md (2.0M+ flips)."
echo "To reproduce one full signature:  \$WORK/opt_160f/sweep \$WORK/runs/160f_t0 sig.bin 0 6724"
