#!/usr/bin/env bash
# Prepare the work trees for the CT-1 timing measurements. The vendor sources are
# NOT bundled; point the variables at the submission's own trees:
#
#   REF     = .../Implementations/Optimized_Implementation/avx2/NEV-R1   (required, the AVX2 tree)
#   REF_REF = .../Implementations/Reference_Implementation/NEV-R1        (optional, portable C tree)
#
# All twelve set directories inside a tree are byte-identical apart from the Makefile;
# the parameter set is chosen by -DPARAMS=1..12, so any set dir works. Nothing under
# $REF / $REF_REF is modified: each tree is copied into ./work/<kind>-{clean,instr} and
# our instrumentation patches (patches/instr-*.patch) are applied to the -instr copy.
#
# The instrumentation only ADDS counter globals (g_scan/g_rej/g_refill/g_veciter/
# g_tailacc in sample.c, g_inv_fail in poly.c). The -clean copy is the pristine
# submission and is what every *timing* binary and every machine-code census uses; the
# -instr copy is used only to CLASSIFY ciphertexts by rejection count, never for timing.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${REF:?set REF=.../Optimized_Implementation/avx2/NEV-R1}"
[ -f "$REF/sample.c" ] && [ -f "$REF/poly.c" ] || { echo "REF=$REF missing sample.c/poly.c" >&2; exit 1; }
mkdir -p "$HERE/work"
prep_tree() { # kind srcdir  -> work/<kind>-clean, work/<kind>-instr
  local kind=$1 src=$2
  rm -rf "$HERE/work/$kind-clean" "$HERE/work/$kind-instr"
  cp -r "$src" "$HERE/work/$kind-clean"
  cp -r "$src" "$HERE/work/$kind-instr"
  ( cd "$HERE/work/$kind-clean" && sed -i 's/\r$//' *.c *.h 2>/dev/null || true )
  ( cd "$HERE/work/$kind-instr" && sed -i 's/\r$//' *.c *.h 2>/dev/null || true )
  patch -s -p1 -d "$HERE/work/$kind-instr" < "$HERE/patches/instr-$kind-sample.patch"
  if [ "$kind" = avx2 ]; then
    patch -s -p1 -d "$HERE/work/$kind-instr" < "$HERE/patches/instr-avx2-poly.patch"
  fi
}
prep_tree avx2 "$REF"
if [ -n "${REF_REF:-}" ] && [ -f "$REF_REF/sample.c" ]; then
  prep_tree ref "$REF_REF"
  echo "prepared work/avx2-{clean,instr} and work/ref-{clean,instr}"
else
  echo "prepared work/avx2-{clean,instr}  (set REF_REF for the portable-C comparison rows)"
fi
