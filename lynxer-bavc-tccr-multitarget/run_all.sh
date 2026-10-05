#!/usr/bin/env bash
# Lynxer (ICCS NGCC round-1, sign-14) -- the BAVC/TCCR seed tree has no per-node tweak, so
# within one signature the T_open revealed nodes form a multi-target set: enumerate hidden
# parents once, hit in 2^lambda/(T_open+1) -> hidden leaf -> u_0 -> witness w -> OWF key k = sk.
#
#   REFROOT="/path/to/Lynxer/Implementations/Reference_Implementation" ./run_all.sh
#
# REFROOT must contain the unmodified vendor instance dirs Lynxer-{256s,256f,384s,512f}
# (each with bavc.c, tccr.c, vole.c, voleith_impl.c, owf.c, sha3/, parameters.h, ...). The
# vendor tree is NEVER modified and NEVER redistributed here: each instance dir is copied to
# work/, our read-only debug hooks are patch'ed into that COPY, and our .c files are compiled
# inside it against the vendor's Keccak backend (WITH_KECCAK_X4 = the ideal-primitive setting;
# the SM3 pseudoXOF placeholder is not used). The patch only adds #ifdef LX_DEMO blocks that
# copy out internal values; it changes no transcript byte (KATs are unaffected).
#
#   [T]  T_open per set and the resulting 2^lambda/(T_open+1) key-recovery cost (parameters.h)
#   [a]  structure: every internal node's children = public TCCR(parent), 4 sets (lx_struct)
#   [b]  end-to-end on 256f, no oracle: scaled-down search against the PUBLIC leaf commitment
#        -> u_0 -> w -> k == secret OWF key, owf(k)=pk, then a FRESH message forged and
#        accepted by the unmodified sig_verify (lx_e2e; B default 24, ~226 s; set B via $1)
set -e -o pipefail
REFROOT="${REFROOT:?set REFROOT=/path/to/Lynxer/Implementations/Reference_Implementation}"
CC="${CC:-cc}"; B="${1:-24}"
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$HERE/src"
VSRCS="bavc.c drng.c enc.c prg.c fields.c instances.c lynx_matrices.c quicksilver.c owf.c random_oracle.c tccr.c universal_hashing.c utils.c voleith_impl.c vole.c auxfunc.c SIG_AlgorithmInstance.c sha3/KeccakHash.c sha3/KeccakHashtimes4.c sha3/KeccakSponge.c sha3/KeccakSpongetimes4.c sha3/opt64/KeccakP-1600-opt64.c sha3/opt64/KeccakP-1600-times4-on1.c"
CF="-O3 -march=native -std=gnu11 -w -D_DEFAULT_SOURCE -DLX_DEMO -DSIG_TESTS -DXOF_PSEUDO -DWITH_KECCAK_X4 -I. -Isha3 -Isha3/opt64"
mkdir -p "$HERE/work"

prep(){ local S=$1; [ -d "$REFROOT/Lynxer-$S" ] || { echo "missing $REFROOT/Lynxer-$S"; exit 1; }
  rm -rf "$HERE/work/$S"; cp -r "$REFROOT/Lynxer-$S" "$HERE/work/$S"
  ( cd "$HERE/work/$S" && patch -p1 -s < "$HERE/patches/lx-demo-hooks.patch" ); }

echo "=== [T] T_open and key-recovery cost per set (from $REFROOT/*/parameters.h) ==="
python3 - "$REFROOT" <<'PY' | sed 's/^/  /'
import sys,re,math,glob,os
root=sys.argv[1]
for S in ["160s","160f","256s","256f","384s","512s","512f"]:
    f=os.path.join(root,f"Lynxer-{S}","parameters.h")
    if not os.path.exists(f): continue
    t=open(f).read(); U=S.upper()
    T=int(re.search(rf"LYNXER_{U}_T_OPEN\s+(\d+)",t).group(1))
    lam=int(re.search(rf"LYNXER_{U}_CSP\s+(\d+)",t).group(1))
    cost=lam-math.log2(T+1)
    tgt=128 if lam==160 else lam
    note=" (unaffected: >target)" if lam==160 else ""
    print(f"Lynxer-{S}: lambda={lam} T_open={T:4d}  key recovery ~2^{cost:.1f}  claimed {tgt}{note}")
PY

for S in 256s 256f 384s 512f; do
  echo; echo "=== [a] $S: position-independence of the seed tree (lx_struct) ==="
  prep $S
  U=$(echo $S | tr a-z A-Z)
  ( cd "$HERE/work/$S" && $CC $CF -DLX_PID=LYNXER_$U "$SRC/lx_struct.c" $VSRCS -o lx_struct -lm && ./lx_struct ) | sed 's/^/  /'
done

echo; echo "=== [b] 256f: end-to-end key recovery + fresh-message forgery, no oracle (lx_e2e, B=$B) ==="
( cd "$HERE/work/256f" && $CC $CF "$SRC/lx_e2e.c" $VSRCS -o lx_e2e -lm && ./lx_e2e "$B" ) | sed 's/^/  /'

echo; echo "=== full-size cost (not executed) ==="
echo "  key recovery from ONE signature = 2^lambda/(T_open+1) TCCR evals: 256 ~2^248.2, 384 ~2^375.6, 512 ~2^503.2"
echo "  (the only unexecuted link; every other step ran above on the submitted code)"
