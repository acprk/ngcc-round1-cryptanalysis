#!/usr/bin/env bash
# Reproduce the NEV CT-1 ternary3 timing channel (and its negative controls) against a
# vendor reference tree.
#
#   REF=.../Optimized_Implementation/avx2/NEV-R1 \
#   [REF_REF=.../Reference_Implementation/NEV-R1] ./run_all.sh [PARAMS ...]
#
# Default sets: 6 (=R3, recommended) and 12 (=C3*). PARAMS 4/5 (R1/R2) are the
# no-rejection negative sets. Timing is core-pinned with taskset -c $CORE (default 100;
# set CORE= to your isolated core, or CORE=none to disable pinning). ABSOLUTE cycle
# counts are hardware-specific; what reproduces across machines is: rejections/decap
# ~= 21.97 with 0 refills under SHA3, a strictly MONOTONE and roughly linear
# slope vs rejection count, sign-correct class separation, and a signal many times the
# same-class control. The reference slope figures quoted in the README are for an Intel
# Xeon Gold 6230R (Cascade Lake); yours will differ in magnitude but not in shape.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SETS=("$@"); [ ${#SETS[@]} -eq 0 ] && SETS=(6 12)
CORE=${CORE:-100}
M=${M:-20000}; PAIRS=${PAIRS:-2000}; BATCHES=${BATCHES:-15}; SLOPEREPS=${SLOPEREPS:-400}
TS="taskset -c $CORE"; [ "$CORE" = none ] && TS=""
mkdir -p "$HERE/logs" "$HERE/data" "$HERE/bin"

echo "== [0] prepare work trees (copy REF, apply instrumentation patches)"
REF="${REF:?}" REF_REF="${REF_REF:-}" "$HERE/prep.sh"

echo "== [1] division-instruction census (KyberSlash check)"
"$HERE/divscan.sh" >/dev/null; tail -1 "$HERE/logs/divscan.txt"; grep "TOTAL" "$HERE/logs/divscan.txt" 2>/dev/null || true
echo "   (full matrix in logs/divscan.txt)"

echo "== [2] conditional-jump census: ternary3 keeps its secret compare (from divscan objects)"
python3 "$HERE/brscan.py" "$HERE/obj/avx2-p6-USE_SHA3/sample.o" ternary3 poly_bias8 cbd3 2>/dev/null | tee "$HERE/logs/brscan_p6.txt" || true

for P in "${SETS[@]}"; do
  for BK in USE_SHA3 USE_ICCS; do
    echo "== [3] PARAMS=$P $BK : classify honest + tampered ciphertexts by rejection count"
    "$HERE/build.sh" avx2 $P $BK gen
    $TS "$HERE/bin/gen_avx2_p${P}_${BK}" $M "$HERE/data/cts_avx2_p${P}_${BK}.bin" 0 | tee "$HERE/logs/gen_p${P}_${BK}.txt"
    $TS "$HERE/bin/gen_avx2_p${P}_${BK}" $M "$HERE/data/tam_avx2_p${P}_${BK}.bin" 1 | tee "$HERE/logs/gen_tam_p${P}_${BK}.txt"

    echo "== [4] PARAMS=$P $BK : paired timing LOW vs HIGH (ab) + negative controls (aa,bb)"
    "$HERE/build.sh" avx2 $P $BK time
    for m in ab aa bb; do
      $TS "$HERE/bin/time_avx2_p${P}_${BK}" "$HERE/data/cts_avx2_p${P}_${BK}.bin" $m $PAIRS $BATCHES \
        | tee "$HERE/logs/time_p${P}_${BK}_$m.txt" | grep SUMMARY
    done
    echo "   on REJECTED (tampered) ciphertexts:"
    $TS "$HERE/bin/time_avx2_p${P}_${BK}" "$HERE/data/tam_avx2_p${P}_${BK}.bin" ab $PAIRS $BATCHES \
      | tee "$HERE/logs/time_tam_p${P}_${BK}.txt" | grep SUMMARY

    echo "== [5] PARAMS=$P $BK : graded slope vs exact rejection count (0 inversions expected)"
    "$HERE/build.sh" avx2 $P $BK slope
    $TS "$HERE/bin/slope_avx2_p${P}_${BK}" "$HERE/data/cts_avx2_p${P}_${BK}.bin.all" $SLOPEREPS \
      | tee "$HERE/logs/slope_p${P}_${BK}.txt" | grep -E "SLOPE|^ *[0-9]"
  done

  echo "== [6] PARAMS=$P : isolated poly_sample_r slope (attributes the leak to ternary3)"
  "$HERE/build.sh" avx2 $P USE_SHA3 seeds
  $TS "$HERE/bin/seeds_avx2_p${P}" 200000 "$HERE/data/seeds_p${P}.bin" | tee "$HERE/logs/seeds_p${P}.txt"
  "$HERE/build.sh" avx2 $P USE_SHA3 smp
  $TS "$HERE/bin/smp_avx2_p${P}" "$HERE/data/seeds_p${P}.bin" 15000 | tee "$HERE/logs/sampler_slope_p${P}.txt" | grep SLOPE

  echo "== [7] PARAMS=$P : fixed-vs-fixed (message dependence) + key dependence (both with null controls)"
  "$HERE/build.sh" avx2 $P USE_SHA3 fvf
  $TS "$HERE/bin/fvf_avx2_p${P}" 3000 | tee "$HERE/logs/fvf_p${P}.txt" | grep SUMMARY
  "$HERE/build.sh" avx2 $P USE_SHA3 keys
  $TS "$HERE/bin/keys_avx2_p${P}_USE_SHA3" 4000     | tee "$HERE/logs/keys_p${P}.txt"     | grep SUMMARY
  $TS "$HERE/bin/keys_avx2_p${P}_USE_SHA3" 4000 dup | tee "$HERE/logs/keys_dup_p${P}.txt" | grep SUMMARY

  echo "== [8] PARAMS=$P : keygen mont2_inverse retry census (CT-5, expect 0)"
  "$HERE/build.sh" avx2 $P USE_SHA3 kgr
  $TS "$HERE/bin/kgr_avx2_p${P}" 20000 | tee "$HERE/logs/keygen_retry_p${P}.txt"
done

# no-rejection negative sets (R1/R2): message dependence must be at the noise floor
for P in 4 5; do
  echo "== [9] PARAMS=$P (no-rejection set) : fixed-vs-fixed must match its own null"
  "$HERE/build.sh" avx2 $P USE_SHA3 fvf
  $TS "$HERE/bin/fvf_avx2_p${P}" 3000 | tee "$HERE/logs/fvf_p${P}.txt" | grep SUMMARY
done
echo "done; logs in $HERE/logs"
