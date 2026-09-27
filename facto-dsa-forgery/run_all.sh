#!/usr/bin/env bash
# Facto-DSA public-key-only universal forgery, end-to-end at level 128.
# Recovers the hidden kernel K2 from the PUBLIC KEY by a restricted Groebner basis, forges on the
# degenerate quadratic coset, and checks the forged signature against the UNMODIFIED reference verifier.
#
#   REF="/path/to/Reference_Implementation/Facto-DSA-128" ./run_all.sh
#
# REF must contain SIG_AlgorithmInstance.c, auxfunc.c, drng.c (the reference is NOT bundled and is
# never modified; tool.c/verify.c only #include / link it to expose keygen, hash-to-field, verify).
# Requires: gcc, python3, and Magma (for the Groebner step). The secret key is read only by an
# optional cross-check, never to guide the attack.
set -e
LVL="${LVL:-128}"; N="${N:-10}"; M="${M:-13}"
REF="${REF:-../src/Facto-DSA/Implementations and Test_Vectors/Implementations/Resource_Implementation/Facto-DSA-$LVL}"
CC="${CC:-gcc}"
mkdir -p keys

echo "=== build harness against the unmodified reference ($REF) ==="
$CC -O2 -I"$REF" src/tool.c   "$REF/auxfunc.c" "$REF/drng.c" -o tool$LVL
$CC -O2 -I"$REF" src/verify.c "$REF/SIG_AlgorithmInstance.c" "$REF/auxfunc.c" "$REF/drng.c" -o verify$LVL

echo "=== 1. reference keygen + public message hash (public path only) ==="
./tool$LVL keygen keys/pk$LVL.bin keys/sk$LVL.bin
echo "forge me $(date +%s)" > keys/m$LVL.txt
./tool$LVL hash keys/pk$LVL.bin keys/m$LVL.txt | tr -d '\n' > keys/h$LVL.txt
python3 src/pk2magma.py keys/pk$LVL.bin $N $M keys/pk$LVL.m

echo "=== 2. recover K2 = ker L2 from the PUBLIC KEY (restricted Groebner, ~11 min) ==="
magma -b src/grobner_k2.m            # writes the verified K2 basis to keys/k2_$LVL.m

echo "=== 3. universal forgery from pk + K2 (~3 min) ==="
magma -b src/forge4.m                # writes keys/zsig.txt

echo "=== 4. verify the forged signature with the UNMODIFIED reference verifier ==="
python3 -c "import struct; z=eval(open('keys/zsig.txt').read()); open('keys/forged$LVL.sig','wb').write(b''.join(struct.pack('<H',x) for x in z))"
./verify$LVL keys/pk$LVL.bin keys/m$LVL.txt keys/forged$LVL.sig
echo "(rc 0 = forged signature ACCEPTED by the reference verifier; a changed message is rejected.)"
