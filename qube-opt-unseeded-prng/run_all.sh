#!/usr/bin/env bash
# QUBE (kem-33) optimized implementation: the internal PRNG is never seeded on the API path.
#   REF=/path/to/QUBE/Implementations ./run_all.sh
# REF must contain Optimized_Implementation/ and Reference_Implementation/ from the ICCS
# submission package. Nothing in $REF is modified: trees are copied to ./work/ and every edit
# (KAT nonce, extra CMake target, the one-function fix for the control) is applied to the copy.
# Runtime ~3-5 min (mostly compilation). Requires cmake >= 3.10, gcc with AVX2.
set -euo pipefail
: "${REF:?set REF to the QUBE Implementations directory}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$HERE/work; OUT=$HERE/out; rm -rf "$W" "$OUT"; mkdir -p "$W" "$OUT"
SETS="1:128 3:256 4:384 5:512"   # optimized targets qube-N <-> QUBE-level (vendor README)
JOBS=${JOBS:-4}

# $1 variant: orig | fixed     $2 KAT nonce (4 chars, the ICCS harness uses "seed")
prep_opt() {
  local d=$W/opt-$1-$2; cp -r "$REF/Optimized_Implementation" "$d"
  sed -i "s/memcpy(nonce + 4 \* i, \"seed\", 4);/memcpy(nonce + 4 * i, \"$2\", 4);/" "$d/tests/kat_kem.c"
  grep -q "\"$2\", 4" "$d/tests/kat_kem.c" || { echo "nonce edit failed" >&2; exit 1; }
  if [ "$1" = fixed ]; then
    ( cd "$d" && patch -s -p1 < "$HERE/patches/seed-prng-from-drng.patch" )
  fi
  { echo "set(QUBE_TOOL_SRC $HERE/src/qube_tool.c)"; cat "$HERE/src/tool.cmake"; } >> "$d/CMakeLists.txt"
  cmake -S "$d" -B "$d/b" -DCMAKE_BUILD_TYPE=Release >"$d.build.log" 2>&1
  for s in $SETS; do n=${s%%:*}; cmake --build "$d/b" --target kat-opt-$n qube-tool-$n -j"$JOBS" >>"$d.build.log" 2>&1 || { echo "build failed, see $d.build.log" >&2; exit 1; }; done
  ( mkdir -p "$d/run" && cd "$d/run" && for s in $SETS; do "$d/b/bin/kat-opt-${s%%:*}" >/dev/null; done )
}
prep_ref() { # control: unmodified reference implementation, KAT harness only
  local d=$W/ref-$1-$2; cp -r "$REF/Reference_Implementation/qube-$1" "$d"
  sed -i "s/memcpy(nonce + 4 \* i, \"seed\", 4);/memcpy(nonce + 4 * i, \"$2\", 4);/" "$d/test/KAT_KEM.c"
  { cmake -S "$d" -B "$d/b" && cmake --build "$d/b" --target kat_qube_$1 -j"$JOBS"; } >"$d.build.log" 2>&1 || { echo "build failed, see $d.build.log" >&2; exit 1; }
  ( cd "$d/test" && "$d/b/bin/kat-qube-$1" >/dev/null )
}
first() { grep -m1 "^$1 = " "$2" | cut -d' ' -f3 | cut -c1-16; }
same()  { diff <(grep "^$1 = " "$2") <(grep "^$1 = " "$3") >/dev/null && echo identical || echo differ; }

echo "== building (orig/fixed optimized x nonce seed/ZZZZ, reference control)"
for v in orig fixed; do for n in seed ZZZZ; do prep_opt $v $n; done; done
for l in 128 512; do for n in seed ZZZZ; do prep_ref $l $n; done; done

{
echo "== [1] ICCS KAT harness, UNMODIFIED optimized code, API DRNG seeded with nonce 'seed' vs 'ZZZZ'"
for s in $SETS; do l=${s#*:}; a=$W/opt-orig-seed/KAT/KAT_KEM_qube_$l.txt; b=$W/opt-orig-ZZZZ/KAT/KAT_KEM_qube_$l.txt
  printf "  QUBE-%s  Seed(rec0) %s vs %s | all 10 records: PK %s, CT %s, SS %s\n" $l "$(first Seed $a)" "$(first Seed $b)" "$(same PK $a $b)" "$(same CT $a $b)" "$(same SS $a $b)"
done
echo "== [2] control: same harness, optimized code with patches/seed-prng-from-drng.patch"
for s in $SETS; do l=${s#*:}; a=$W/opt-fixed-seed/KAT/KAT_KEM_qube_$l.txt; b=$W/opt-fixed-ZZZZ/KAT/KAT_KEM_qube_$l.txt
  printf "  QUBE-%s  PK %s, CT %s, SS %s\n" $l "$(same PK $a $b)" "$(same CT $a $b)" "$(same SS $a $b)"
done
echo "== [3] control: same harness, unmodified REFERENCE implementation"
for l in 128 512; do a=$(find $W/ref-$l-seed -newer $W/ref-$l-seed/b/bin/kat-qube-$l -name "KAT_KEM_qube_$l.txt" | head -1); b=$(find $W/ref-$l-ZZZZ -newer $W/ref-$l-ZZZZ/b/bin/kat-qube-$l -name "KAT_KEM_qube_$l.txt" | head -1)
  printf "  QUBE-%s  PK %s, CT %s, SS %s\n" $l "$(same PK $a $b)" "$(same CT $a $b)" "$(same SS $a $b)"
done
} | tee "$OUT/kat_compare.txt"

{
echo "== [4] attacker recovers the KAT record-0 key and session key (victim run used nonce 'ZZZZ')"
for s in $SETS; do n=${s%%:*}; l=${s#*:}; echo " QUBE-$l"; "$W/opt-orig-seed/b/bin/qube-tool-$n" katrec "$W/opt-orig-ZZZZ/KAT/KAT_KEM_qube_$l.txt"; done

echo "== [5] API DRNG seeded from /dev/urandom in every process (what a correct integrator does)"
T=$W/api; mkdir -p "$T"
for s in $SETS; do n=${s%%:*}; l=${s#*:}; O=$W/opt-orig-seed/b/bin/qube-tool-$n; F=$W/opt-fixed-seed/b/bin/qube-tool-$n; t=$T/$l; mkdir -p "$t"
  # (a) key recovery: victim Alice keygens with the unmodified code; Bob (patched, honest randomness)
  #     encapsulates to her; the attacker runs keygen in its own process and decapsulates Bob's ct.
  $O keygen $t/pkA $t/skA; $F enc $t/pkA $t/ctB $t/ssB
  $O keygen $t/pkX $t/skX; $O dec $t/skX $t/ctB $t/ssX
  # (b) sender side: Carol's key is honest (patched code); victim Dave encapsulates to her with the
  #     unmodified code; the attacker, knowing only Carol's pk, runs the public encapsulation in its
  #     own process. SCORING ONLY: Carol's real sk confirms ssD is the session key she derives.
  $F keygen $t/pkC $t/skC; $O enc $t/pkC $t/ctD $t/ssD
  $O enc $t/pkC $t/ctY $t/ssY; $F dec $t/skC $t/ctD $t/ssC
  r() { cmp -s "$1" "$2" && echo YES || echo NO; }
  printf "  QUBE-%s (a) attacker pk == Alice pk: %s | attacker sk == Alice sk: %s | attacker ss == Bob ss: %s\n" $l "$(r $t/pkX $t/pkA)" "$(r $t/skX $t/skA)" "$(r $t/ssX $t/ssB)"
  printf "  QUBE-%s (b) attacker ct == Dave ct: %s | attacker ss == Dave ss: %s | [scoring] Carol decaps == Dave ss: %s\n" $l "$(r $t/ctY $t/ctD)" "$(r $t/ssY $t/ssD)" "$(r $t/ssC $t/ssD)"
done
} | tee "$OUT/attack.txt"
echo "done; outputs in $OUT"
