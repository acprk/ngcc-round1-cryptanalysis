#!/usr/bin/env bash
# Qing Luan (ICCS NGCC round-1, sign-20): two observations, end to end.
#
#   REF="/path/to/Implementations and Test_Vectors/Implementations/Reference_Implementation" ./run_all.sh
#
# [A] multi-pipe SM3 (second-)preimage is ~2^{(P-1)*256}, not the claimed 2^{2λ}  (pure Python, scaled model)
# [C] signing re-expands the secret eta with a variable-length rejection sampler  (links REF's unmodified C)
# REF must contain the unmodified QingLuan-128/-256/-384/-512 dirs; nothing under REF is modified or redistributed.
# Options: KEYS=3000 (keys per level for [C]), LEVELS="128 256 384 512", CC=gcc, SKIP_A=1.
set -e
REF="${REF:?set REF=/path/to/Reference_Implementation}"
CC="${CC:-gcc}"; KEYS="${KEYS:-3000}"; LEVELS="${LEVELS:-128 256 384 512}"
HERE="$(cd "$(dirname "$0")" && pwd)"; mkdir -p "$HERE/work"; cd "$HERE/work"

if [ -z "$SKIP_A" ]; then
  echo "=== [A1] Joux second preimage on a P-pipe concatenation (scaled pipe width n0) ==="
  python3 "$HERE/joux/joux_secondpreimage.py" | grep -E "P = |JOUX|d K / d n0" | sed 's/^/  /'
  echo; echo "=== [A2] multi-target: distinct salt prefixes vs shared-salt positive control ==="
  python3 "$HERE/joux/multitarget.py" | grep -E "slope|DISTINCT|SHARED" | head -8 | sed 's/^/  /'
fi

echo; echo "=== [C] eta re-expansion trace (sign.c ExpandSK -> rsdp_gen_secret_exp -> rsdp_csprng_fz) ==="
grep -n "rsdp_gen_secret_exp" "$REF/QingLuan-512/src/sign.c" | sed 's/^/  sign.c:/'
grep -n -A7 "^uint8_t rsdp_csprng_fz" "$REF/QingLuan-512/src/rsdp.c" | sed 's/^/  rsdp.c:/'
for L in $LEVELS; do
  ln -sfn "$REF/QingLuan-$L" "ql$L"; S="ql$L/src"
  "$CC" -O2 -std=c11 -I"ql$L/include" -Dxof_squeeze=xof_squeeze_counted -c "$S/rsdp.c" -o "rsdp_counted$L.o"
  "$CC" -O2 -std=c11 -I"ql$L/include" -o "probe$L" "$HERE/ct-sampler/probe.c" "$HERE/ct-sampler/count.c" "rsdp_counted$L.o" \
      $S/fq_arith.c $S/hash.c $S/utils.c $S/restr.c $S/mpc.c $S/keygen.c $S/sign.c $S/verify.c
  "./probe$L" "$KEYS" > "probe$L.csv"
  python3 "$HERE/ct-sampler/analyze.py" "$L" "probe$L.csv"
done
