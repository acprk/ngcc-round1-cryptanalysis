#!/usr/bin/env bash
# PolarLAC-Light: HONEST NEGATIVE result.
#   The finding is a REAL non-constant-time decapsulation (the FO re-encryption rejection
#   count R leaks via timing). It is NOT exploitable into a key recovery: the message-flip
#   timing oracle a chosen-ciphertext recovery needs has 68-99% per-query error, and the
#   end-to-end timing recovery is 0/512.
#
#   REF=/path/to/Reference_Implementation/POLARLAC-Light ./run_all.sh
#
# The reference implementation is NOT bundled; obtain it from the ICCS submission package.
# The re-investigation harnesses link the UNMODIFIED reference and recompute R offline from
# the reference's own exported routines, so NO source patch is required. src/ is never modified.
set -e
REF="${REF:-./ref/POLARLAC-Light}"
CORE="${CORE:-100}"
CC="${CC:-gcc}"
CFLAGS="${CFLAGS:--O3 -march=native -std=gnu11 -I$REF -Isrc}"
[ -d "$REF" ] || { echo "REF not found: $REF (point REF at the PolarLAC-Light reference sources)"; exit 1; }

# reference .c except the KAT / self-test drivers
REFSRC=$(ls "$REF"/*.c 2>/dev/null | grep -vE 'KAT_KEM|/test\.c|cycles_test' | tr '\n' ' ')

echo "=== build the re-investigation timing harnesses against the unmodified reference ==="
$CC $CFLAGS harnesses/reinvestigate/harness_time.c   $REFSRC -o harness_time   -lm
$CC $CFLAGS harnesses/reinvestigate/harness_oracle.c $REFSRC -o harness_oracle -lm
$CC $CFLAGS harnesses/scratch_canary/sweep.c         $REFSRC -o sweep          -lm

echo "=== (1) THE FINDING: real timing leak -- R-class separation (~9k cyc/rejection) ==="
taskset -c "$CORE" ./harness_time

echo "=== (2) THE NEGATIVE: message-flip TIMING oracle per-query error (naive + canary baselines) ==="
taskset -c "$CORE" ./harness_oracle

echo "=== (3) WHY: clean-bit vs R-gap trade-off; EXACT-R oracle-error ceiling (=> 0/512) ==="
taskset -c "$CORE" ./sweep

cat <<'EOF'
=== conclusion ===
The timing leak is REAL (decapsulation is non-constant-time; R leaks ~9k cycles/rejection,
R-bucket classifier error ~0.4-0.9%). It is NOT exploitable: the message-flip predicate a
key recovery needs cannot be read from the clock (68-99% per-query error; the clean-bit and
R-gap requirements conflict), so an end-to-end timing key recovery is 0/512.

The algebraic recovery machinery in src/attack.c + src/finish.c DOES recover the full key,
but ONLY when handed an idealised plaintext-checking oracle (direct plaintext access), which
the clock cannot supply. That path is NOT a timing attack and is NOT claimed as a break.
Fix: constant-iteration, message-independent re-encryption sampling.
EOF
