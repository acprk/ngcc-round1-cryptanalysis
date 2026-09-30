#!/usr/bin/env bash
# Full spec-literal demonstration (F-1, F-2, F-3) end to end.
#   REF=/path/.../Reference_Implementation/NEV-C1 \
#   TV=/path/.../NEV/Test_Vectors ./run_all.sh
# REF = any one reference set dir (all 12 are identical apart from the Makefile).
# TV  = the submission's Test_Vectors dir (read-only; nothing copied into the repo).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${REF:?set REF=/path/to/NEV/Implementations/Reference_Implementation/NEV-C1}"
: "${TV:?set TV=/path/to/NEV/Test_Vectors}"
echo "########## step 1: Algorithm-11 self-check + Fig.4 falsification"
"$HERE/run_selfcheck.sh" 2000
echo; echo "########## steps 2-4: KAT differential (base must reproduce 12/12; F-3 changes all 12)"
"$HERE/run_kat.sh"
echo; echo "########## step 5: cross interoperability (R1/D1 fail; other 10 sets interoperate)"
"$HERE/run_interop.sh" 200
echo; echo "########## step 5b: attribution -- which deviation changes the ciphertext"
"$HERE/run_isolate_encap.sh"
echo; echo "done; logs in $HERE/logs (kat_diff.txt, interop.txt, isolate_encap.txt, selfcheck.txt, multiset.txt)"
