#!/usr/bin/env bash
# TriQ-KEX timing-oracle evidence. Demonstrates that static-key decapsulation is
# not constant-time: the FO re-encryption's bounded-density resampler leaks the
# decrypted message via its (early-break) iteration count.
#
#   REF=/path/to/Reference_Implementation/TriQ-KEX-128 ./run_all.sh
#
# For a clean signal the timing harness MUST be pinned to an isolated idle core;
# on a loaded/powersave host the channel is swamped by scheduler/freq-scaling jitter.
set -e
CORE="${CORE:-3}"           # isolated idle core to pin to; override with CORE=N
N="${N:-4000}"; REP="${REP:-31}"
make -s all
echo "=== per-iteration cost (micro) ==="
taskset -c "$CORE" ./micro
echo
echo "=== full-decapsulation timing by BD-resample class (pinned core $CORE) ==="
taskset -c "$CORE" ./harness_bdtime "$N" "$REP"
echo
echo "=== decode-oracle structural probe (key-recovery groundwork) ==="
./exp_oracle 4 120
echo "done."
