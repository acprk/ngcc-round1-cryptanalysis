#!/usr/bin/env bash
# Build the "spec-literal" work tree: a copy of ONE NEV reference-implementation set
# with our three deviation patches applied. The reference sources are NOT bundled;
# point REF at a set directory of the submission's Reference_Implementation, e.g.
#
#   REF=/path/to/NEV/Implementations/Reference_Implementation/NEV-C1
#
# All twelve reference set directories are byte-identical apart from the Makefile's
# default target, and the parameter set is selected only by -DPARAMS=1..12, so any
# one of them works as REF. Nothing under $REF is modified: the set is copied into
# ./work/spec and the patches are applied to the copy.
#
# The three patches (patches/spec-f{1,2,3}-*.patch) only ADD code behind
# -DSPEC_F1 / -DSPEC_F2 / -DSPEC_F3 switches (plus the always-present
# cbd_eta_alg11 self-check helper). With no switch defined, the patched tree is
# byte-for-byte the submitted algorithm; the switches turn on Noise2Pt (F-1),
# Algorithm-11 CBD (F-2) and the Algorithm-15 keypair nonce order (F-3).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${REF:?set REF=/path/to/NEV/Implementations/Reference_Implementation/NEV-C1 (or any set dir)}"
[ -f "$REF/pack.c" ] && [ -f "$REF/sample.c" ] && [ -f "$REF/owpke.c" ] || {
  echo "REF=$REF does not look like a NEV reference set dir (missing pack.c/sample.c/owpke.c)" >&2; exit 1; }

WORK="$HERE/work/spec"
rm -rf "$HERE/work"; mkdir -p "$HERE/work"
cp -r "$REF" "$WORK"
# CRLF hygiene (some submission trees ship CRLF); harmless if already LF
( cd "$WORK" && sed -i 's/\r$//' *.c *.h 2>/dev/null || true )
for p in spec-f1-noise2pt spec-f2-cbd-alg11 spec-f3-keypair-nonce; do
  patch -s -p1 -d "$WORK" < "$HERE/patches/$p.patch"
done
# sanity: the switch-less build must equal the submission -- checked by run_kat.sh's
# variant `base`, which we build from the SAME work tree with no -DSPEC_* flag.
echo "$WORK"
