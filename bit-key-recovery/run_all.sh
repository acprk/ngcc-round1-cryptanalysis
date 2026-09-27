#!/usr/bin/env bash
# Full BiT-128 key recovery from honest signatures: shared-sign bilinear estimator,
# bias-kernel deconvolution calibrated on the attacker's OWN key, and a public-relation
# finisher, then a forgery against the unmodified reference verifier.
#
#   REF=/path/to/Reference_Implementation/BiT-128 ./run_all.sh
#
# The recovery uses only public data (pk + honest signatures) and the attacker's own
# calibration keypair. The victim secret key.bin is read ONLY inside deconv.py's
# [SCORING] block (grep -n 'SK-READ' src/deconv.py).
set -e
REF="${REF:-./ref/BiT-128}"
PY="${PY:-python3}"          # needs numpy
VSIG="${VSIG:-250000}"       # victim sigs per worker (x4) -> 1M total
CSIG="${CSIG:-250000}"       # calibration sigs per worker (x4) -> 1M total

# keep a full transcript of every run next to the artifacts
exec > >(tee run_all.log) 2>&1
echo "run_all: $(date -Is)  VSIG=${VSIG}x4  CSIG=${CSIG}x4  REF=$REF"

make -s REF="$REF"

# run 4 workers of $1 with $2 sigs each into ${3}{A,B,C,D}.bin; wait on their PIDs only
# (a bare `wait` would also wait on the tee above) and fail if any worker fails
par4(){ local pids=() meta=1; for x in A B C D; do ./"$1" "$2" "$3$x.bin" $meta & pids+=($!); meta=0; done
  for p in "${pids[@]}"; do wait "$p"; done; }

echo "=== [$(date +%T)] victim: honest signatures under a fresh key (pk.bin/key.bin dumped) ==="
par4 gen_fixed "$VSIG" sig

echo "=== [$(date +%T)] attacker calibration: signatures under a DIFFERENT own key (calkey.bin dumped) ==="
par4 gen_cal "$CSIG" cal

echo "=== [$(date +%T)] bilinear estimator ==="
./est2 sigA.bin sigB.bin sigC.bin sigD.bin && mv acc2.bin acc2_victim.bin
./est2 calA.bin calB.bin calC.bin calD.bin && mv acc2.bin acc2_cal.bin
# optional control: independent random sign (models a scheme without the shared bimodal bit)
# (ctrl mode writes acc2_ctrl.bin itself)
./est2 ctrl sigA.bin sigB.bin sigC.bin sigD.bin

echo "=== [$(date +%T)] deconvolve (kernel fit on the calibration key) -> s0_rec.bin ==="
"$PY" src/deconv.py

echo "=== [$(date +%T)] public-relation finisher + forgery vs the unmodified reference verifier ==="
./forge
echo "=== [$(date +%T)] done ==="
