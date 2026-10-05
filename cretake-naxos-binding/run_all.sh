#!/usr/bin/env bash
# CreTAKE (kex-03): the initiator-side bit/byte length-unit error removes the
# NAXOS binding between the ephemeral key and the long-term secret, so a single
# permitted state reveal recovers the session key; and the KEX wrappers ignore
# the caller-supplied message lengths, giving pre-authentication out-of-bounds
# reads on truncated messages.
#
#   REF=/path/to/CreTAKE/Implementations ./run_all.sh
#
# REF must contain Reference_Implementation/ and Optimized_Implementation/
# exactly as in the ICCS submission package (CreTAKE.zip). Nothing in $REF is
# modified: each tree is copied into ./work/ and all building/patching happens
# on the copy. Runtime a few minutes. Requires gcc (AVX2 for the opt tree).
set -uo pipefail
: "${REF:?set REF to the CreTAKE Implementations directory}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$HERE/work; OUT=$HERE/logs; rm -rf "$W"; mkdir -p "$W" "$OUT"
SRC=$HERE/src
CC=${CC:-gcc}
N=${N:-20}          # trials per instance for the state-reveal experiment
LOG=$OUT/run.txt; : > "$LOG"
say(){ echo "$@" | tee -a "$LOG"; }

# Copy a whole tree once; we build instances in place inside the copy.
prep_tree(){ # $1 = Reference_Implementation | Optimized_Implementation
  local t=$1
  [ -d "$W/$t" ] && return 0
  cp -r "$REF/$t" "$W/$t"
}

# Extract an instance's include/library flags and CFLAGS from its own Makefile.
inst_flags(){ # $1 = instance dir ; sets global INC LIBS CF
  local d=$1 I
  I=$(cd "$d" && make -s --no-print-directory --eval 'pi: ; @echo $(INCLUDES) $(KEM_LIB) $(SIG_LIB)' pi)
  INC=$(echo "$I" | tr ' ' '\n' | grep '^-I' | tr '\n' ' ')
  LIBS=$(echo "$I" | tr ' ' '\n' | grep '\.a$' | tr '\n' ' ')
  CF=$(cd "$d" && make -s --no-print-directory --eval 'pi: ; @echo $(CFLAGS)' pi)
}

# ---- Experiment 1: single state reveal recovers the session key (F1) --------
# Builds the instance normally, then links one of three variants of
# KEX_AlgorithmInstance against attack_state.c:
#   (none)   : submitted code                      -> expect recovered = N/N
#   fixed    : the one call changed to *8 bits      -> expect recovered = 0/N (control)
#   fix0301  : only the responder call from kex-03-1 fixed -> expect recovered = N/N
run_state(){ # $1 = tree  $2 = instance subpath  $3 = variant(""|fixed|fix0301)
  local tree=$1 inst=$2 variant=${3:-} d="$W/$1/$2" tag
  prep_tree "$tree"
  ( cd "$d" && make -s clean all >/dev/null 2>&1 ) || { say "[build-fail] $tree/$inst"; return; }
  inst_flags "$d"
  local kexo="KEX_AlgorithmInstance.o" tmpc="" tmpo=""
  if [ "$variant" = fix0301 ]; then
    tmpc=$(mktemp --suffix=.c); tmpo=$(mktemp --suffix=.o)
    sed 's/buf, SEED_BYTES, buf2/buf, SEED_BYTES * 8, buf2/' "$d/KEX_AlgorithmInstance.c" > "$tmpc"
    ( cd "$d" && $CC $CF $INC -c "$tmpc" -o "$tmpo" ) || { say "[patch-fail] $inst"; return; }
    kexo="$tmpo"
  elif [ "$variant" = fixed ]; then
    tmpc=$(mktemp --suffix=.c); tmpo=$(mktemp --suffix=.o)
    sed 's/SEED_BYTES + SKI_LEN, seed_kg/(SEED_BYTES + SKI_LEN) * 8, seed_kg/' "$d/KEX_AlgorithmInstance.c" > "$tmpc"
    ( cd "$d" && $CC $CF $INC -c "$tmpc" -o "$tmpo" ) || { say "[patch-fail] $inst"; return; }
    kexo="$tmpo"
  fi
  tag="$tree${variant:+/$variant}"
  ( cd "$d" && $CC -O2 -w -std=c99 $INC "$SRC/attack_state.c" "$kexo" \
        auxfunc.o drng.o secure_bzero.o $LIBS -o atk ) \
    || { say "[link-fail] $tag $inst"; rm -f "$tmpc" "$tmpo"; return; }
  ( cd "$d" && N=$N ./atk "$N" ) 2>/dev/null \
    | grep -E 'RESULT|absorbed_bytes' | sed "s#^#[$tag] #" | tee -a "$LOG"
  rm -f "$d/atk" "$tmpc" "$tmpo"
}

# ---- Experiment 1b: LCP(pk, sk) and which bytes are absorbed -----------------
run_lcp(){ # $1 = tree  $2 = instance subpath
  local d="$W/$1/$2"; prep_tree "$1"
  ( cd "$d" && make -s clean all >/dev/null 2>&1 ) || return
  inst_flags "$d"
  ( cd "$d" && $CC -O2 -w -std=c99 $INC "$SRC/lcp.c" KEX_AlgorithmInstance.o \
        auxfunc.o drng.o secure_bzero.o $LIBS -o lcp && ./lcp ) | tee -a "$LOG"
  rm -f "$d/lcp"
}

# ---- Experiment 2: truncated message -> heap OOB read (F2), under ASan -------
run_trunc(){ # $1 = tree  $2 = instance subpath
  local tree=$1 inst=$2 d="$W-asan/$1/$2" which L rc
  mkdir -p "$W-asan"
  [ -d "$W-asan/$tree" ] || cp -r "$REF/$tree" "$W-asan/$tree"
  ( cd "$d" && make -s CC="gcc -fsanitize=address,undefined -fno-omit-frame-pointer -g" clean all >/dev/null 2>&1 ) \
    || { say "[asan-build-fail] $tree/$inst"; return; }
  inst_flags "$d"
  ( cd "$d" && gcc -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -w -std=c99 $INC \
        "$SRC/poc_trunc.c" KEX_AlgorithmInstance.o auxfunc.o drng.o secure_bzero.o $LIBS -o poc ) \
    || { say "[asan-link-fail] $tree/$inst"; return; }
  for which in m1 m2; do for L in 1 16 63; do
    rc=$(cd "$d" && ASAN_OPTIONS=detect_leaks=0 ./poc "$L" "$which" 2>&1 \
          | grep -oE 'heap-buffer-overflow|READ of size [0-9]+|SEGV|SURVIVED' | head -2 | paste -sd' ' )
    say "[$tree-asan] $inst $which L=$L -> ${rc:-ok}"
  done; done
  rm -f "$d/poc"
}

say "=== CreTAKE kex-03: NAXOS binding (F1) + caller-length OOB read (F2) ==="
say "REF=$REF   date=$(date -u +%FT%TZ)   host=$(uname -srm)"
say ""
say "--- [F1] single state reveal recovers the session key (recovered should be N/N) ---"
# Reference tree: all six S2K + six S2S instances (the signature-bearing frameworks).
for i in \
  CreTAKE128/CreTAKE-S2K-BiT128-PLAC128 CreTAKE128/CreTAKE-S2K-BiT128-ZEN128 \
  CreTAKE128/CreTAKE-S2S-BiT128-ePLAC128 CreTAKE128/CreTAKE-S2S-BiT128-eZEN128 \
  CreTAKE256/CreTAKE-S2K-BiT256-PLAC256 CreTAKE256/CreTAKE-S2K-BiT256-ZEN256 \
  CreTAKE256/CreTAKE-S2S-BiT256-ePLAC256 CreTAKE256/CreTAKE-S2S-BiT256-eZEN256 \
  CreTAKE512/CreTAKE-S2K-BiT512-PLAC512 CreTAKE512/CreTAKE-S2K-BiT512-ZEN512 \
  CreTAKE512/CreTAKE-S2S-BiT512-ePLAC512 CreTAKE512/CreTAKE-S2S-BiT512-eZEN512 ; do
  run_state Reference_Implementation "$i"
done
say ""
say "--- [F1] same, Optimized tree (two ZEN256 instances segfault for the unrelated AVX2 alignment reason; see P.S. in the comment) ---"
for i in \
  CreTAKE128/CreTAKE-S2K-BiT128-PLAC128 CreTAKE128/CreTAKE-S2K-BiT128-ZEN128 \
  CreTAKE128/CreTAKE-S2S-BiT128-ePLAC128 CreTAKE128/CreTAKE-S2S-BiT128-eZEN128 \
  CreTAKE256/CreTAKE-S2K-BiT256-PLAC256 CreTAKE256/CreTAKE-S2K-BiT256-ZEN256 \
  CreTAKE256/CreTAKE-S2S-BiT256-ePLAC256 CreTAKE256/CreTAKE-S2S-BiT256-eZEN256 \
  CreTAKE512/CreTAKE-S2K-BiT512-PLAC512 CreTAKE512/CreTAKE-S2K-BiT512-ZEN512 \
  CreTAKE512/CreTAKE-S2S-BiT512-ePLAC512 CreTAKE512/CreTAKE-S2S-BiT512-eZEN512 ; do
  run_state Optimized_Implementation "$i"
done
say ""
say "--- [F1 control] change only this call to *8 bits -> recovered should drop to 0/N ---"
for i in CreTAKE128/CreTAKE-S2K-BiT128-PLAC128 CreTAKE128/CreTAKE-S2S-BiT128-eZEN128 \
         CreTAKE512/CreTAKE-S2K-BiT512-ZEN512 CreTAKE512/CreTAKE-S2S-BiT512-ePLAC512 ; do
  run_state Reference_Implementation "$i" fixed
done
say ""
say "--- [F1 de-dup] fix ONLY the responder call named by kex-03-1 -> still N/N ---"
for i in CreTAKE128/CreTAKE-S2K-BiT128-PLAC128 CreTAKE128/CreTAKE-S2S-BiT128-eZEN128 \
         CreTAKE512/CreTAKE-S2S-BiT512-ePLAC512 ; do
  run_state Reference_Implementation "$i" fix0301
done
say ""
say "--- [F1 witness] LCP(pk,sk): every absorbed sk byte is a public-key byte (absorbed_is_public=YES) ---"
for i in CreTAKE128/CreTAKE-S2S-BiT128-eZEN128 CreTAKE256/CreTAKE-S2S-BiT256-ePLAC256 \
         CreTAKE512/CreTAKE-S2S-BiT512-ePLAC512 ; do
  run_lcp Reference_Implementation "$i"
done
say ""
say "--- [F2] truncated message -> heap-buffer-overflow READ (ASan) ---"
for i in CreTAKE128/CreTAKE-K2S-ZEN128-BiT128 CreTAKE128/CreTAKE-S2S-BiT128-eZEN128 \
         CreTAKE256/CreTAKE-K2S-ZEN256-BiT256 CreTAKE512/CreTAKE-K2S-ZEN512-BiT512 ; do
  run_trunc Reference_Implementation "$i"
done
say ""
say "=== done.  Full transcript in $LOG ==="
