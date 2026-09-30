#!/usr/bin/env bash
# AFS-KEX (pMAKE-BW) protocol-layer verification, all three levels.
#   REFROOT="/path/to/AFS-KEX/Implementations and Test_Vectors" ./run_all.sh
# REFROOT must contain Implementations/Reference_Implementation/AFS_KEX_{C128,C256,C512}.
# NOTE: the submission path contains a space; we symlink each level to a space-free name
# so the C toolchain include/搜索 paths stay clean. Nothing under REFROOT is modified.
set -e
REFROOT="${REFROOT:-../src/AFS-KEX/Implementations and Test_Vectors}"
RID="$REFROOT/Implementations/Reference_Implementation"
CC="${CC:-gcc-11}"
TR="${TR:-200}"
LNK="$(mktemp -d)"
trap 'rm -rf "$LNK"' EXIT
for L in C128 C256 C512; do
  echo "======================= AFS_KEX_$L ======================="
  ln -sfn "$RID/AFS_KEX_$L" "$LNK/AFS_KEX_$L"
  make -s CC="$CC" REF="$LNK/AFS_KEX_$L" all
  ./negatives
  ./failure_oracle "$TR"
  ./uks_keycopy "$TR"
  ./reply3_refute "$TR"
  ./replay_impersonate "$TR"
  make -s REF="$LNK/AFS_KEX_$L" clean
  echo
done
echo "done."
