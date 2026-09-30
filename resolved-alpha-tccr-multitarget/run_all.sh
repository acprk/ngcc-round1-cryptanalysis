#!/usr/bin/env bash
# ReSolveD-alpha (ICCS NGCC round-1, sign-21) -- within-signature multi-target seed search on the
# BAVC/TCCR tree (no per-node tweak) -> key recovery -> forgery.  End to end, from public data.
#
#   REFROOT="/path/to/ReSolveD-alpha/Implementations/Reference_Implementation" ./run_all.sh
#
# REFROOT must contain the unmodified vendor instance dirs ReSolveD-alpha-{256s,256f,384s,512f}
# (each with bavc.c, tccr.c, vole.c, voleith_impl.c, sha3/, parameters.h, ...).  The reference is
# NEVER modified and NEVER redistributed here: each instance dir is copied to work/, our .c files are
# compiled inside that copy (they #include the vendor sources) with the vendor's Keccak backend
# (WITH_KECCAK_X4 = the ideal-primitive setting; the SM3 pseudoXOF placeholder is not used).
#
#   [T ]  |id-list| distribution per parameter set (tcount.py, from the vendor parameters.h)
#   [a ]  structure: every revealed node = public function of its hidden parent, 4 sets (h2_witness)
#         + oracle-fed key-recovery chain (hidden parent -> leaf -> witness -> forgery)
#   [b ]  NO oracle: genuine self-locating windowed search on a real signature -> witness -> fresh
#         forgery, 4 sets (exp_genuine, B = 20; 256s also B = 22; FULL=1 adds 256s B = 24, ~10 min)
#   [c ]  /T is a real total-work speedup: hash-set membership 0.3 probes/candidate vs linear scan
#         (exp_htable, B = 20 / 24; FULL=1 adds B = 28, ~15 min)
set -e -o pipefail
REFROOT="${REFROOT:?set REFROOT=/path/to/Implementations/Reference_Implementation}"
CC="${CC:-gcc}"; FULL="${FULL:-0}"
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/src"
SRCS="drng.c enc.c prg.c fields.c instances.c quicksilver.c rsd.c random_oracle.c tccr.c universal_hashing.c utils.c auxfunc.c SIG_AlgorithmInstance.c sha3/KeccakHash.c sha3/KeccakHashtimes4.c sha3/KeccakSponge.c sha3/KeccakSpongetimes4.c sha3/opt64/KeccakP-1600-opt64.c sha3/opt64/KeccakP-1600-times4-on1.c"
mkdir -p "$HERE/work"
prep(){ # prep <set>  -> copies the vendor instance into work/<set> (vendor tree untouched)
  local S=$1; [ -d "$REFROOT/ReSolveD-alpha-$S" ] || { echo "missing $REFROOT/ReSolveD-alpha-$S"; exit 1; }
  rm -rf "$HERE/work/$S"; cp -r "$REFROOT/ReSolveD-alpha-$S" "$HERE/work/$S"; }
build(){ # build <set> <prog.c> <out>
  local S=$1 U=$(echo $1 | tr a-z A-Z); ( cd "$HERE/work/$S" && "$CC" -O2 -march=native -std=gnu99 -w \
    -DWITH_KECCAK_X4 -Isha3 -Isha3/opt64 -I. -DSETID=RESOLVED_ALPHA_$U "$SRC/$2" $SRCS -o "$3" -lm ); }

echo "=== [T] |id-list| distribution (from $REFROOT/*/parameters.h) ==="
python3 "$SRC/tcount.py" "$REFROOT" | sed 's/^/  /'

for S in 256s 256f 384s 512f; do
  echo; echo "=== [a] $S: structure check + oracle-fed key-recovery chain (h2_witness) ==="
  prep $S; build $S h2_witness.c h2_witness; ( cd "$HERE/work/$S" && ./h2_witness 2 ) | sed 's/^/  /'
done

for S in 256s 256f 384s 512f; do
  echo; echo "=== [b] $S: GENUINE self-locating search (no oracle) -> witness -> fresh-message forgery (exp_genuine) ==="
  build $S exp_genuine.c exp_genuine
  for B in 20 $([ $S = 256s ] && echo 22) $([ "$FULL" = 1 ] && [ $S = 256s ] && echo 24); do ( cd "$HERE/work/$S" && ./exp_genuine $B ) | sed 's/^/  /'; done
done

echo; echo "=== [c] 256-bit TCCR: hash-set (O(1)) vs linear-scan (O(T)) membership, T=216 (exp_htable) ==="
( cd "$HERE/work/256s" && "$CC" -O2 -march=native -std=gnu99 -w -I. "$SRC/exp_htable.c" tccr.c enc.c fields.c utils.c drng.c auxfunc.c -o exp_htable -lm )
( cd "$HERE/work/256s" && ./exp_htable 20 216 200 && ./exp_htable 24 216 30 && { [ "$FULL" = 1 ] && ./exp_htable 28 216 4 || true; } ) | sed 's/^/  /'

echo; echo "=== full-size cost (extrapolation) ==="
echo "  key recovery from ONE signature = 2^lambda/(T+1) TCCR evals: 256 ~2^248.2, 384 ~2^375.6, 512 ~2^503.2 (160: ~2^153, above target)"
echo "  (not executed; every other link of the attack ran above on the submitted code)"
