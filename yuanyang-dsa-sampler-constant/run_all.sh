#!/usr/bin/env bash
# Build our harness against the vendor reference and reproduce the B2 measurements.
#   REF=/path/to/YuanYang.DSA/Implementations/Reference_Implementation/yuanyang-512 ./run_all.sh [N]
# N defaults to 20000 (about 1 min single core); N=400000 reproduces the 10-sigma regression (about 19 min per key).
# Nothing in $REF is modified: it is copied to ./work/<variant> and the patches are applied to the copies.
set -euo pipefail
: "${REF:?set REF to the yuanyang-512 reference implementation directory}"
N=${1:-20000}
HERE=$(cd "$(dirname "$0")" && pwd)
CORE="common.c prng.c fpr.c fft.c auxfunc.c drng.c ntt.c codec.c poly_inv_ntt.c SIG_AlgorithmInstance.c sign.c sign_ntt.c vrfy.c sampler.c keygen/keygen.c keygen/pairgen.c keygen/perturbation.c keygen/fft.c keygen/security_loss.c keygen/ntrugen/src/ntrugen.c keygen/ntrugen/src/bigint.c keygen/ntrugen/src/bigintgcd.c keygen/ntrugen/src/cfft.c keygen/ntrugen/src/complex.c keygen/ntrugen/src/fft.c keygen/ntrugen/src/twiddles9.c"
build() { # $1 variant name, $2.. patches
  local v=$1; shift; local w=$HERE/work/$v
  rm -rf "$w"; mkdir -p "$HERE/work"; cp -r "$REF" "$w"
  ( cd "$w" && sed -i 's/\r$//' *.c *.h keygen/*.c keygen/*.h 2>/dev/null || true )
  for p in "$@"; do ( cd "$w" && patch -p1 < "$HERE/patches/$p" ); done
  ( cd "$w" && mkdir -p obj && for f in $CORE; do gcc -std=gnu99 -O2 -I. -Ikeygen -Ikeygen/ntrugen/src -c "$f" -o "obj/$(echo "$f" | tr / _).o"; done && ar rcs libyy.a obj/*.o
    for t in gapstat samp1d dumpkey vcheck; do gcc -O2 -I. -o $t "$HERE/src/$t.c" libyy.a -lm; done )
}
mkdir -p "$HERE/out"
build orig
build b2fixed b2-large-sampler-constant.patch
build allfixed b2-large-sampler-constant.patch b1-perturbation-covariance.patch b3-delta2-exponent.patch
echo "== 1-D large sampler moments (orig / B2 fixed)"; work/orig/samp1d 400000 | head -2; work/b2fixed/samp1d 400000 | head -2
echo "== keys (SCORING dumps)"; work/orig/dumpkey 0 > out/key0.txt; work/orig/dumpkey 7 > out/key7.txt
echo "== transcript statistics, original reference, N=$N, keys 0 and 7"
work/orig/gapstat "$N" 0 40 out/mu_orig_k0.txt | tee out/orig_k0.out
work/orig/gapstat "$N" 7 40 out/mu_orig_k7.txt | tee out/orig_k7.out
echo "== transcript statistics after the B2 patch"
work/b2fixed/gapstat "$N" 0 40 out/mu_b2fixed_k0.txt | tee out/b2fixed_k0.out
echo "== transcript statistics after B1+B2+B3"
work/allfixed/gapstat "$N" 0 40 out/mu_allfixed_k0.txt | tee out/allfixed_k0.out
work/allfixed/vcheck | tee out/vcheck_allfixed.txt
echo "== secret-dependence regression"
python3 "$HERE/src/regress_mean.py" "$N" out/key0.txt out/mu_orig_k0.txt out/key7.txt out/mu_orig_k7.txt | tee out/regress_orig.txt
