#!/usr/bin/env bash
# Tins one-signature secret-witness recovery on the authors' own KAT vectors, at all
# three levels, against the UNMODIFIED reference implementation.
#
#   REFROOT="/path/to/Implementations/Reference_Implementation" \
#   KATDIR="/path/to/tins/Test_Vectors" ./run_all.sh
#
# Recovery uses only the public key and one signature (both taken from the submitted KAT).
# The reference is NOT bundled and src/ is never modified.
set -e
REFROOT="${REFROOT:-../src/Tins/tins/Implementations/Reference_Implementation}"
KATDIR="${KATDIR:-../src/Tins/tins/Test_Vectors}"
extract(){ awk -v w="$1" '$1==w && $2=="="{print $3; exit}' "$2"; }

for L in 128 256 512; do
  echo "=== Tins-$L : recover (alpha,beta) from pk + one KAT signature ==="
  ./build.sh "$REFROOT/Tins$L"
  extract PK "$KATDIR/KAT_SIG_Tins$L.txt" > /tmp/tins_pk.hex
  extract Sn "$KATDIR/KAT_SIG_Tins$L.txt" > /tmp/tins_sn.hex
  ./attack /tmp/tins_pk.hex /tmp/tins_sn.hex | head -1
done
echo
echo "Each line reports 'recovered witness satisfies NSBC: YES': the full signing witness"
echo "(alpha,beta) is recovered from ONE signature and the public key, on the authors' own"
echo "KAT vectors, against the unmodified reference. Universal forgery follows: the attacker"
echo "now holds the witness and signs arbitrary messages with the genuine signing algorithm."
