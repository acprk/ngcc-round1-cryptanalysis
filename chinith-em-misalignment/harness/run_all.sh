#!/usr/bin/env bash
# Reproduce the completeness failure of uBlockith-EM (and Vistrutith) once a_tilde_0 is bound.
#
#   REF=/path/to/Chinith/Implementations/Reference_Implementation ./run_all.sh
#
# For each of ublockith_d3_256f (control), ublockith_em_d3_256f, vistrutith_d3_512f the script
# copies the vendor tree into ./build/, applies patch_a0check.py (hash a_tilde_0 into chall_3 in
# signer AND verifier, and print whether the verifier's reconstructed a_tilde_0 equals the
# signer's), builds the vendor bench target and runs 5 sign/verify rounds.
#   expected:  non-EM control  -> "YES" 5/5
#              EM              -> "NO"  5/5   (misaligned constraints)
#              Vistrutith      -> "NO"  5/5   (wrong QuickSilver aggregation)
# Then the EM tree is rebuilt with patch_em_offset_fix.py (skip S0 when passing the encryption
# witness: w+32 bytes, tags/keys +256) -> "YES" 5/5.
# Finally ublock_kat.c checks the vendor uBlock-256/256 core against the public test vector.
set -euo pipefail
: "${REF:?set REF to the vendor Reference_Implementation directory}"
H="$(cd "$(dirname "$0")" && pwd)"; B="$H/build"; mkdir -p "$B"
JOBS="${JOBS:-4}"

for s in ublockith_d3_256f ublockith_em_d3_256f vistrutith_d3_512f; do
  d="$B/${s}_a0chk"; rm -rf "$d"; cp -r "$REF/$s" "$d"
  python3 "$H/patch_a0check.py" "$(ls "$d"/utils_*/sig_impl_*.c)"
  ( cd "$d" && make -j"$JOBS" "${s}_bench" >/dev/null && echo "== $s (a_tilde_0 bound)" \
    && "./${s}_bench" 5 2>&1 | grep a0check | sort | uniq -c )
done

d="$B/ublockith_em_d3_256f_emfix"; rm -rf "$d"; cp -r "$B/ublockith_em_d3_256f_a0chk" "$d"
python3 "$H/patch_em_offset_fix.py" "$d/utils_ublock/ublockith_ublock_256.c"
( cd "$d" && make clean >/dev/null && make -j"$JOBS" >/dev/null && echo "== EM + one-block offset fix" \
  && ./ublockith_em_d3_256f_bench 5 2>&1 | grep a0check | sort | uniq -c )

d="$B/vistrutith_d3_512f_valchk"; rm -rf "$d"; cp -r "$B/vistrutith_d3_512f_a0chk" "$d"
python3 "$H/patch_vistrutith_valchk.py" "$d/utils_vistrutah/vistrutith_vistrutah_512.c"
( cd "$d" && make clean >/dev/null && make -j"$JOBS" >/dev/null && echo "== Vistrutith clear-text constraint values" \
  && ./vistrutith_d3_512f_bench 2 2>&1 | grep -E "valchk|a0check" )

U="$B/ublockith_d3_256f_a0chk"
gcc -O2 -std=c11 -I"$U" -I"$U/utils_ublock" -include "$U/fallbacks.h" "$H/ublock_kat.c" \
    "$U/utils_ublock/ublock_core.c" "$U/utils.c" -o "$B/ublock_kat" && "$B/ublock_kat"
