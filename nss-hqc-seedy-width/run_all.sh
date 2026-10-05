#!/usr/bin/env bash
# NSS-HQC (kem-26): HQC-384 / HQC-512 decryption key is determined by a 256-bit sub-seed.
#   REF=/path/to/NSS-HQC/Implementations/Reference_Implementation ./run_all.sh
# REF must contain HQC-128/ HQC-256/ HQC-384/ HQC-512/ from the ICCS submission package
# (Optimized_Implementation/ is byte-identical to it). Nothing in $REF is modified: each level is
# copied to ./work/, and the scale-model edit of step [2] is applied to a separate copy only.
# Env: BITS (scale-model seed_y width, default 8), K (false-positive control size, default 32).
# Runtime: a few minutes (HQC-512 costs ~0.3-0.5 s per candidate on our host).
set -euo pipefail
: "${REF:?set REF to the NSS-HQC Reference_Implementation directory}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$HERE/work; OUT=$HERE/out; rm -rf "$W" "$OUT"; mkdir -p "$W" "$OUT"
BITS=${BITS:-8}; K=${K:-32}
CFLAGS="-std=gnu99 -O2 -w"

build() { # $1 level  $2 variant: orig | scaled
  local d=$W/HQC-$1-$2; cp -r "$REF/HQC-$1" "$d"
  if [ "$2" = scaled ]; then
    # SCALE MODEL ONLY: keep the low $BITS bits of the 256-bit seed_y right after derive_xy_seeds
    # splits SHA3-512(seed_sk). Keygen and decapsulation both go through this function.
    sed -i "/memcpy(seed_y, digest + NSS_HQC_I_SEED_BYTES, NSS_HQC_I_SEED_BYTES);/a\\
    { unsigned bb; for (bb = DEMO_SEEDY_BITS; bb < 8u*NSS_HQC_I_SEED_BYTES; bb++) seed_y[bb>>3] \\&= (uint8_t)~(1u<<(bb\\&7)); }" "$d/nss_hqc_core.c"
    grep -q "DEMO_SEEDY_BITS" "$d/nss_hqc_core.c" || { echo "scale-model edit failed" >&2; exit 1; }
    gcc $CFLAGS -DDEMO_SEEDY_BITS="$BITS" -I"$d" -o "$W/tool-$1-$2" "$HERE/src/nss_seedy_tool.c" "$d/code_layer.c" "$d/auxfunc.c" "$d/drng.c"
  else
    gcc $CFLAGS -I"$d" -o "$W/tool-$1-$2" "$HERE/src/nss_seedy_tool.c" "$d/code_layer.c" "$d/auxfunc.c" "$d/drng.c"
  fi
}

echo "== building"
for l in 128 256 384 512; do build $l orig; done
for l in 384 512; do build $l scaled; done

{
echo "== [0] source: I() = SHA3-512 split into two 32-byte sub-seeds, at every level"
for l in 128 256 384 512; do
  printf "  HQC-%s  %s | %s\n" $l "$(grep -h 'define NSS_HQC_SEED_SK_BYTES' "$REF/HQC-$l/params.h" | tr -d '\r' | xargs)" \
    "$(grep -h 'define NSS_HQC_I_SEED_BYTES' "$REF/HQC-$l/nss_hqc_core.c" | tr -d '\r' | xargs)"
done
echo "== [1] full size, UNMODIFIED code: y is a function of seed_y alone and decrypts on its own"
for l in 128 256 384 512; do "$W/tool-$l-orig" full "$K"; done
echo "== [2] attack, scale model: victim seed_y restricted to $BITS bits; attacker sees pk and ct only"
for l in 384 512; do "$W/tool-$l-scaled" search "$BITS"; done
echo "== [3] control: same attacker search against the UNMODIFIED code (must not find)"
for l in 384 512; do "$W/tool-$l-orig" search "$BITS"; done
} 2>&1 | tee "$OUT/run.txt"
