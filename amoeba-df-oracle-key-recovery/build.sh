#!/usr/bin/env bash
# Build the Amoeba decryption-failure-oracle key-recovery harness against the reference.
# The harness #includes the reference cpapke.c and probes CPAPKE_Decrypt (whose !=0 return
# is the pre-FO decryption-failure oracle). Reference NOT bundled; src/ never modified.
#   ./build.sh "/path/to/Reference_Implementation/Amoeba-576"
set -e
REF="$1"; CC="${CC:-gcc-11}"
[ -d "$REF" ] || { echo "usage: ./build.sh <Reference_Implementation/Amoeba-LEVEL dir>"; exit 1; }
BK="$REF/src/backend"; SYM="$REF/src/symmetric"
# link all backend+symmetric .c EXCEPT cpapke.c (it is #included by the harness), ccakem/kem,
# and the KAT/test/API mains; C99 'inline' NTT helpers need -fgnu89-inline to emit definitions.
OTHER=$(ls "$BK"/*.c "$SYM"/*.c 2>/dev/null | grep -vE 'cpapke.c|ccakem.c|/kem\.c|main|test|PQCgen|KAT|AlgorithmInstance' | sort -u)
$CC -O2 -fgnu89-inline -I"$BK" -I"$SYM" src/amoeba_dfo_keyrec.c $OTHER -o attack -lm
echo "built ./attack against $REF"
