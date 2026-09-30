#!/usr/bin/env bash
# OPS-SIG (ICCS NGCC round-1, sign-17) -- spec-conformance break, end to end.
#
#   REF="/path/to/Reference_Implementation/OPSsig-128" ./run_all.sh
#
# REF must be an unmodified vendor reference instance dir (sign.c, poly.c, rounding.c, mult.c,
# packing.c, polyvec.c, ntt.c, reduce.c, auxfunc.c, drng.c, params.h, *.h).  The reference is NEVER
# modified and NEVER redistributed here; our files only link it and swap ONE function via the
# preprocessor (-Dpoly_challenge=... / -Ddecompose=... rename the reference symbol so ours wins).
#
# Shows three things, all from public data:
#   [F1a] spec SampleInBall (Alg.6) -> FIXED challenge support {n-tau..n-1}, challenge space 2^tau
#   [F1b] public-key-only forgery accepted by the spec verifier; rejected on other msg and by the
#         shipped/reference sampler (controls).  Completed at a toy tau; real cost = 2^tau * (us/try).
#   [F2 ] spec Decompose/UseHint (Alg.30/32) -> honest signatures fail their OWN verification.
# The shipped reference binary is correct throughout (this is a spec<->code discrepancy).
set -e
REF="${REF:?set REF=/path/to/Reference_Implementation/OPSsig-128}"
CC="${CC:-gcc}"; STD="-O2 -std=c99"
TOYTAU="${TOYTAU:-20}"; SEED="${SEED:-1}"
SRCS="sign.c mult.c packing.c polyvec.c ntt.c reduce.c auxfunc.c drng.c"   # poly.c/rounding.c handled per-build
OBJS="sign.o mult.o packing.o polyvec.o ntt.o reduce.o auxfunc.o drng.o"
cc(){ "$CC" $STD -I"$REF" "$@"; }
mkdir -p work; cd work

echo "=== build against the unmodified reference ==="
echo "    REF=$REF"
for f in $SRCS; do cc -c "$REF/$f" -o "${f%.c}.o"; done
cc -c "$REF/poly.c"     -o poly_ref.o
cc -c "$REF/rounding.c" -o rounding_ref.o
cc -Dpoly_challenge=poly_challenge_REF -c "$REF/poly.c" -o poly_specsampler.o
cc -Ddecompose=decompose_REF -Duse_hint=use_hint_REF -c "$REF/rounding.c" -o rounding_specround.o
cc -c ../src/spec_sampler.c  -o spec_sampler.o
cc -c ../src/spec_rounding.c -o spec_rounding.o

echo; echo "=== [F1a] challenge support: spec Alg.6 vs the shipped reference sampler ==="
cc ../src/dist_check.c poly_specsampler.o spec_sampler.o rounding_ref.o $OBJS -lm -o dc_spec
cc ../src/dist_check.c poly_ref.o rounding_ref.o $OBJS -lm -o dc_ref
echo   "  spec Alg.6 :"; ./dc_spec | sed 's/^/     /'
echo   "  reference  :"; ./dc_ref  | sed -n '1p;3p' | sed 's/^/     /'

echo; echo "=== [F2] honest verification-failure rate: spec Alg.30/32 vs reference rounding ==="
cc ../src/honest_fail.c poly_ref.o rounding_specround.o spec_rounding.o $OBJS -o hf_spec
cc ../src/honest_fail.c poly_ref.o rounding_ref.o $OBJS -o hf_ref
printf "  spec rounding : "; ./hf_spec 20 100
printf "  reference     : "; ./hf_ref  20 100

echo; echo "=== [F1b] public-key-only forgery vs the spec verifier (toy TAU=$TOYTAU, completed) ==="
# Override TAU only for files that #include "params.h" (auxfunc.c does not), via an include shim.
mkdir -p toyinc
printf '#ifndef OPS_TOY_PARAMS\n#define OPS_TOY_PARAMS\n#include "%s/params.h"\n#undef TAU\n#define TAU %s\n#endif\n' "$REF" "$TOYTAU" > toyinc/params.h
tcc(){ "$CC" $STD -Itoyinc -I"$REF" "$@"; }
tcc -Dpoly_challenge=poly_challenge_REF -c "$REF/poly.c" -o poly_specsampler_toy.o
tcc -c ../src/spec_sampler.c -o spec_sampler_toy.o
TOYBASE=""; for f in $SRCS; do tcc -c "$REF/$f" -o "toy_${f%.c}.o"; TOYBASE="$TOYBASE toy_${f%.c}.o"; done
tcc -c "$REF/poly.c"     -o toy_poly.o
tcc -c "$REF/rounding.c" -o toy_rounding.o
tcc ../src/forge.c      poly_specsampler_toy.o spec_sampler_toy.o toy_rounding.o $TOYBASE -lm -o forge_spec
tcc ../src/verify_ref.c toy_poly.o             toy_rounding.o $TOYBASE -lm -o verify_ref
./forge_spec forged.bin "$SEED" | sed 's/^/  /'
echo "  -- control: shipped/reference sampler on the SAME forged signature --"
./verify_ref forged.bin | sed 's/^/  /'

echo; echo "=== real-parameter cost (extrapolation) ==="
echo "  per-try cost is TAU-independent; real OPS levels: L1 tau=39 -> 2^39, L3 tau=45 -> 2^45, L5 tau=90 -> 2^90"
echo "  (2^39 hashes ~ feasible; far below the 128-bit / 2*lambda=256-bit forgery target)."
