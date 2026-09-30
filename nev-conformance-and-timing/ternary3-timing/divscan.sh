#!/usr/bin/env bash
# Machine-code division-instruction census (the KyberSlash check) over the prepared
# CLEAN work trees. Run ./prep.sh first. Scans avx2 (and ref, if REF_REF was set) at
# -O3 -march=native with the submission's own /usr/bin/gcc.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
CC=${CC:-/usr/bin/gcc}
OUT="$HERE/logs/divscan.txt"; mkdir -p "$HERE/logs" "$HERE/obj"
: > "$OUT"
printf "%-5s %-4s %-9s %-9s %-9s %-7s %-9s %s\n" tree set backend obj Tsyms div divany size >> "$OUT"
TREES="avx2"; [ -d "$HERE/work/ref-clean" ] && TREES="ref avx2"
for TREE in $TREES; do
  T="$HERE/work/$TREE-clean"
  for P in 4 5 6 12; do for BK in USE_SHA3 USE_ICCS; do
    D="$HERE/obj/$TREE-p$P-$BK"; mkdir -p "$D"
    for f in poly sample verify pack ntt; do
      $CC -Wno-incompatible-pointer-types -mavx2 -mpopcnt -mbmi2 -msse2 -march=native -mtune=native \
          -O3 -fomit-frame-pointer -std=c99 -I"$T" -I"$T/symmetrics" -DPARAMS=$P -D$BK \
          -c "$T/$f.c" -o "$D/$f.o" 2>>"$HERE/logs/build_err.txt" || { echo "BUILDFAIL $TREE p$P $BK $f" >> "$OUT"; continue; }
      nsym=$(nm --defined-only "$D/$f.o" | grep -c ' T ')
      ndiv=$(objdump -d "$D/$f.o" | grep -cE '\b(idivl|idivq|idivw|idivb|divl|divq|divw|divb)\b' || true)
      ndivany=$(objdump -d "$D/$f.o" | grep -cE '\b(idiv|div)' || true)
      sz=$(stat -c%s "$D/$f.o")
      printf "%-5s P%-3s %-9s %-9s %-9s %-7s %-9s %s\n" "$TREE" "$P" "$BK" "$f.o" "$nsym" "$ndiv" "$ndivany" "$sz" >> "$OUT"
    done
  done; done
done
cat "$OUT"
echo "TOTAL div/idiv: $(awk 'NR>1{s+=$6} END{print s}' "$OUT")"
