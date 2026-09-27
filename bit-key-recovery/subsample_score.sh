#!/usr/bin/env bash
# Recovery vs. number of victim signatures, from ONE stored 2M-signature victim run
# (sig{A,B,C,D}.bin, 500k each) and the stored 1M calibration run (cal*.bin, calkey.bin).
# Disjoint subsamples: "a" = first part of every worker file, "b" = last part.
# Runs in a temp dir; the stored artifacts in this directory are not modified.
#   PY=/usr/bin/python3 ./subsample_score.sh
set -e
PY="${PY:-python3}"; H=$PWD; S=2560   # bytes per stored record: 5 polys x 256 x int16
D=$(mktemp -d); cd "$D"; mkdir src; cp "$H"/src/deconv.py src/; cp "$H"/{est2,forge,pk.bin,key.bin,calkey.bin,acc2_cal.bin} .
f(){ printf '%s ' "$H/sigA.bin" "$H/sigB.bin" "$H/sigC.bin" "$H/sigD.bin"; }
run(){ tag=$1; shift; ./est2 "$@" && mv acc2.bin acc2_victim.bin; echo "--- $tag"
  "$PY" src/deconv.py | grep 'SCORING\]'; ./forge | grep -E 'fix|RESULT|final'; }
Q=$((125000*S)); M=$((250000*S))
run "0.5M a" <(head -c $Q "$H/sigA.bin") <(head -c $Q "$H/sigB.bin") <(head -c $Q "$H/sigC.bin") <(head -c $Q "$H/sigD.bin")
run "0.5M b" <(tail -c $Q "$H/sigA.bin") <(tail -c $Q "$H/sigB.bin") <(tail -c $Q "$H/sigC.bin") <(tail -c $Q "$H/sigD.bin")
run "1M a"   <(head -c $M "$H/sigA.bin") <(head -c $M "$H/sigB.bin") <(head -c $M "$H/sigC.bin") <(head -c $M "$H/sigD.bin")
run "1M b"   <(tail -c $M "$H/sigA.bin") <(tail -c $M "$H/sigB.bin") <(tail -c $M "$H/sigC.bin") <(tail -c $M "$H/sigD.bin")
run "2M"     $(f)
