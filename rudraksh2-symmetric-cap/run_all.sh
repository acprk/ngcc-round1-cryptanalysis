#!/usr/bin/env bash
# Reproduce the Rudraksh2 (kem-34) findings against a vendor reference tree.
#
#   REF=/path/to/Rudraksh2/Implementations ./run_all.sh          # findings 1 & 2 (~1 min)
#   REF=/path/to/Rudraksh2/Implementations ./run_all.sh --latt   # + lattice recompute (~15 min)
#
# REF must be the submission's Implementations/ directory, i.e. it must contain
#   Reference_Implementation/lwekem{128,256,512}
#   Optimized_Implementation/lwekem{128,256,512}          (AVX2; *.S + *.inc)
#   Additional_Implementations/Cortex_M4/lwekem{L}/crypto_kem/Rudraksh2/Rudraksh2
#   Test_Vectors/KAT_KEM_lwekem{128,256,512}.txt
#
# Nothing under $REF is modified: each set is copied to ./work/<impl>-<L> and the
# one-line M4 fix is applied to the copy. No vendor source or binary is included here.
set -euo pipefail
: "${REF:?set REF to the Rudraksh2 Implementations directory}"
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-gcc}
mkdir -p "$HERE/work" "$HERE/out"

REFI="$REF/Reference_Implementation"
OPTI="$REF/Optimized_Implementation"
M4I="$REF/Additional_Implementations/Cortex_M4"
TV="$REF/Test_Vectors"

impl_dir() { # $1 impl  $2 level  ->  echoes the vendor source dir
  case $1 in
    ref) echo "$REFI/lwekem$2" ;;
    opt) echo "$OPTI/lwekem$2" ;;
    m4)  echo "$M4I/lwekem$2/crypto_kem/Rudraksh2/Rudraksh2" ;;
  esac
}

prep() { # $1 impl  $2 level  ->  echoes a work dir with vendor sources copied in
  local w="$HERE/work/$1-$2"
  rm -rf "$w"; mkdir -p "$w"
  local d; d=$(impl_dir "$1" "$2")
  cp "$d"/*.c "$d"/*.h "$w"/ 2>/dev/null || true
  cp "$d"/*.S "$d"/*.inc "$w"/ 2>/dev/null || true    # AVX2 assembly, if any
  rm -f "$w/kex.c"                                     # dead Kyber-era code, does not compile
  [ -f "$w/KAT_KEM.c" ] || cp "$REFI/lwekem$2/KAT_KEM.c" "$w"/   # M4/opt may lack the KAT driver
  echo "$w"
}

cflags() { case $1 in opt) echo "-mavx2 -mbmi2 -mpopcnt" ;; *) echo "" ;; esac; }

build_cross() { # $1 impl  $2 level  $3 workdir
  local srcs; srcs=$(ls "$3"/*.c | grep -v 'KAT_KEM.c')
  $CC -O2 -fcommon -w $(cflags "$1") -I"$3" -DHDR="\"KEM_lwekem$2.h\"" \
     "$HERE/src/cross.c" $srcs $(ls "$3"/*.S 2>/dev/null) -o "$3/cross"
}

build_kat() { # $1 impl  $2 level  $3 workdir
  ( cd "$3" && $CC -O2 -fcommon -w $(cflags "$1") -I. *.c $(ls *.S 2>/dev/null) -o KAT_KEM \
       && ./KAT_KEM >/dev/null 2>&1 )
}

kat_status() { # $1 workdir  $2 level  -> MATCH / MISMATCH
  local f="$1/output/KAT_KEM_lwekem$2.txt"
  [ -f "$f" ] || f=$(ls "$1"/output/* 2>/dev/null | head -1)
  if [ -n "${f:-}" ] && cmp -s "$f" "$TV/KAT_KEM_lwekem$2.txt"; then echo MATCH; else echo MISMATCH; fi
}

echo "=============================================================================="
echo " Finding 1 -- 512-level secret key AND session key are functions of a 256-bit"
echo "              SM3 chaining value (claimed classical 512 / quantum 256)"
echo "=============================================================================="
{
  echo "-- [1a] session key = G(m || H(pk)) is a function of the lenK-byte message + pk"
  echo "        alone (independent of ct): generic Grover message search ~2^(4*lenK)"
  for L in 128 256 512; do
    w=$(prep ref "$L")
    srcs=$(ls "$w"/*.c | grep -v 'KAT_KEM.c')
    $CC -O2 -fcommon -w -I"$w" -DHDR="\"KEM_lwekem$L.h\"" "$HERE/src/keycap.c" $srcs -o "$w/keycap"
    printf "  %s-set  " "$L"; "$w/keycap"
  done
  echo "  claimed quantum: 128->80, 256->128, 512->256  (128 set: 2^64 < 80; 512 set: see [1b])"
  echo
  echo "-- [1b] 512 set: secret key AND session key rebuilt from the 256-bit SM3 chaining value"
  w=$(prep ref 512)
  srcs=$(ls "$w"/*.c | grep -vE 'KAT_KEM.c|auxfunc.c')   # cap512.c #includes auxfunc.c itself
  $CC -O2 -fcommon -w -I"$w" "$HERE/src/cap512.c" $srcs -o "$w/cap512"
  "$w/cap512"
  echo "  negative control (flip 1 bit of each chaining value; a real experiment must give 0/50):"
  "$w/cap512" --perturb | sed 's/^/  /'
} | tee "$HERE/out/cap512.txt"

echo
echo "=============================================================================="
echo " Finding 2 -- Cortex-M4 128/256 use a different error-correction constant"
echo "              (MINAL_BETA=0) => KAT mismatch and 0-interop with ref/AVX2"
echo "=============================================================================="
echo "-- [2a] KAT vs the submitted Test_Vectors, per implementation:"
{
  for L in 128 256 512; do
    for impl in ref opt m4; do
      w=$(prep "$impl" "$L"); build_kat "$impl" "$L" "$w" || true
      echo "  $impl-$L KAT $(kat_status "$w" "$L")"
    done
  done
} | tee "$HERE/out/kat.txt"

echo "-- [2b] cross-implementation interop (200 sessions per pair, both directions):"
{
  for L in 128 256 512; do
    for impl in ref opt m4; do build_cross "$impl" "$L" "$HERE/work/$impl-$L"; done
    for L2 in "$L"; do :; done
    for e in ref opt m4; do "$HERE/work/$e-$L/cross" enc 200 "$HERE/work/$e-$L/ct.bin"; done
    for e in ref opt m4; do for d in ref opt m4; do
      printf "  L%s enc=%s dec=%s: " "$L" "$e" "$d"
      "$HERE/work/$d-$L/cross" dec "$HERE/work/$e-$L/ct.bin"
    done; done
  done
} | tee "$HERE/out/interop.txt"

echo "-- [2c] the fix: set the M4 128/256 constant to 220 (spec Table 1); re-test:"
{
  for L in 128 256; do
    w="$HERE/work/m4fix-$L"; rm -rf "$w"; cp -r "$HERE/work/m4-$L" "$w"
    sed -i 's/#define MINAL_BETA 0/#define MINAL_BETA 220/' "$w/minal.c"
    grep -q '#define MINAL_BETA 220' "$w/minal.c" || { echo "patch failed" >&2; exit 1; }
    build_cross m4 "$L" "$w"; build_kat m4 "$L" "$w" || true
    "$w/cross" enc 200 "$w/ct.bin"                      # regenerate ciphertexts with the fixed constant
    echo "  m4fix-$L KAT $(kat_status "$w" "$L")"
    printf "  L%s enc=m4fix dec=ref : " "$L"; "$HERE/work/ref-$L/cross" dec "$w/ct.bin"
    printf "  L%s enc=ref   dec=m4fix: " "$L"; "$w/cross" dec "$HERE/work/ref-$L/ct.bin"
  done
} | tee "$HERE/out/fix.txt"

echo
echo "=============================================================================="
echo " Finding 3 -- The -II parameter sets (q=4001) contradict the spec's own NTT"
echo "              requirement: no primitive 2n-th root of unity exists"
echo "=============================================================================="
python3 "$HERE/nttcheck.py" | tee "$HERE/out/nttcheck.txt"

echo
echo "=============================================================================="
echo " Finding 4 -- kem_dec/kem_enc ignore the caller-declared length (OOB read)"
echo "=============================================================================="
if [[ "${1:-}" == "--asan" || "${2:-}" == "--asan" ]]; then
  w=$(prep ref 128)
  srcs=$(ls "$w"/*.c | grep -v 'KAT_KEM.c')
  $CC -O1 -g -fsanitize=address -fcommon -w -I"$w" -DHDR="\"KEM_lwekem128.h\"" \
     "$HERE/src/asan_lenignore.c" $srcs -o "$w/asan" 2>/dev/null
  "$w/asan" 2>&1 | grep -E "heap-buffer-overflow|READ of size|poly_decompress|unpack_ciphertext|SUMMARY|calling kem_dec" | tee "$HERE/out/asan.txt" || true
else
  echo "  (pass --asan to build the AddressSanitizer reproducer; see logs/asan.txt)"
fi

if [[ "${1:-}" == "--latt" ]]; then
  echo
  echo "=============================================================================="
  echo " Finding 5 -- Rudraksh2-II sets vs an ML-KEM-512 anchor (no II implementation)"
  echo "=============================================================================="
  command -v sage >/dev/null || { echo "sage not found; skipping"; exit 0; }
  sage -python "$HERE/latt/latt_II.py" | tee "$HERE/out/latt_II.txt"
fi

echo
echo "done. Outputs in $HERE/out/ ; logs of our own run are in $HERE/logs/"
