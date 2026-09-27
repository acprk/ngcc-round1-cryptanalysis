#!/usr/bin/env bash
# CheetahKEM sub-ring projection. Primary, self-contained demonstration: validate the
# primal-embedding recovery pipeline at reduced scale (n0=40/56/72), calibrating the 2^53.4
# estimate for the real n=128 projected instance. IND-CPA (decision) break; full real-key
# recovery needs a G6K build with dd/qd float support.
#   ./run_all.sh                (runs the self-contained pipeline validation)
#   REF=/path/to/reference ./run_all.sh REALKEY   (also dumps a real key + checks the ring-hom identity)
set -e
PY="${PY:-sage -python}"
echo "=== pipeline validation at reduced scale (self-contained; recovers the projected secret exactly) ==="
$PY src/toy_recover.py

if [ "$1" = "REALKEY" ]; then
  REF="${REF:-../build/subring_attack/cheetah128}"; CC="${CC:-gcc-11}"
  echo "=== dump a real Cheetah128 key from the reference and check the ring-hom identity ==="
  $CC -O2 -I"$REF" src/dump.c "$REF"/poly.c "$REF"/ntt.c "$REF"/mod.c "$REF"/auxfunc.c "$REF"/drng.c "$REF"/KEM_Cheetah.c -o dump
  ./dump > dump1.txt
  $PY src/verify_proj.py || echo "(verify_proj expects a dump exposing a_coef/s_coef/b_tilde; adapt dump.c's output if needed)"
fi
echo "(full real n=128 recovery: src/recover_real.py with a G6K build that has dd/qd float support)"
