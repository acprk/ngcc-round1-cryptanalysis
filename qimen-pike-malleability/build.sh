#!/usr/bin/env bash
# Build the QIMEN-PIKE ciphertext-malleability / DoS demo against the reference project.
#   ./build.sh <QIMEN-PIKE Implementations cmake root>
# The reference implementation is NOT modified: it is copied to a scratch dir, the demo
# source and its CMake target are injected into the copy, and the project is configured
# and built there. Requires cmake and GMP (as the reference itself does).
set -e
REF="$1"
[ -f "$REF/CMakeLists.txt" ] || { echo "usage: ./build.sh <dir containing the project CMakeLists.txt and src/ngcc/>"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
cp -r "$REF"/. "$WORK"/
cp "$HERE/src/malleability_demo.c" "$WORK/src/ngcc/common/malleability_demo.c"
if ! grep -q 'malleability_demo_' "$WORK/src/ngcc/CMakeLists.txt"; then
  cat "$HERE/src/cmake_target.txt" >> "$WORK/src/ngcc/CMakeLists.txt"
fi
mkdir -p "$WORK/build" && ( cd "$WORK/build" && cmake -DCMAKE_BUILD_TYPE=Release .. >/dev/null && \
  cmake --build . --target malleability_demo_1 malleability_demo_2 malleability_demo_3 -j4 >/dev/null )
cp "$WORK"/build/src/ngcc/malleability_demo_1 "$HERE/malleability_demo_1"
cp "$WORK"/build/src/ngcc/malleability_demo_2 "$HERE/malleability_demo_2"
cp "$WORK"/build/src/ngcc/malleability_demo_3 "$HERE/malleability_demo_3"
echo "built $HERE/malleability_demo_{1,2,3} against $REF"
