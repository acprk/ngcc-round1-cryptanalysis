#!/usr/bin/env bash
# Top-level driver for the three NEV (ngcc.dev kem-25) sub-artifacts. Each part is also
# runnable on its own; see the per-part READMEs and the section headers below.
#
#   # (a) exact DFR -- no vendor code needed:
#   ./run_all.sh dfr
#
#   # (b) spec-literal conformance -- needs a reference set dir and the Test_Vectors:
#   REF=/path/.../Reference_Implementation/NEV-C1 TV=/path/.../NEV/Test_Vectors ./run_all.sh spec
#
#   # (c) ternary3 timing channel -- needs the AVX2 (and optionally the reference) tree:
#   REF_AVX2=/path/.../Optimized_Implementation/avx2/NEV-R1 \
#   [REF_PORTABLE=/path/.../Reference_Implementation/NEV-R1] ./run_all.sh timing
#
#   ./run_all.sh all     # run every part for which the needed variables are set
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
what=${1:-all}
run_dfr(){ echo "==================== (a) dfr-exact ===================="; "$HERE/dfr-exact/run.sh"; }
run_spec(){ echo "==================== (b) spec-literal ===================="
  REF="${REF:?spec part needs REF=<reference set dir>}" TV="${TV:?spec part needs TV=<Test_Vectors dir>}" \
    "$HERE/spec-literal/run_all.sh"; }
run_timing(){ echo "==================== (c) ternary3-timing ===================="
  REF="${REF_AVX2:?timing part needs REF_AVX2=<avx2 set dir>}" REF_REF="${REF_PORTABLE:-}" \
    "$HERE/ternary3-timing/run_all.sh"; }
case "$what" in
  dfr) run_dfr ;;
  spec) run_spec ;;
  timing) run_timing ;;
  all)
    run_dfr
    if [ -n "${REF:-}" ] && [ -n "${TV:-}" ]; then run_spec; else echo "[skip spec: set REF and TV]"; fi
    if [ -n "${REF_AVX2:-}" ]; then run_timing; else echo "[skip timing: set REF_AVX2]"; fi ;;
  *) echo "usage: $0 {dfr|spec|timing|all}"; exit 1 ;;
esac
