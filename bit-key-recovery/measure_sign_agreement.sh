#!/usr/bin/env bash
# Measure P(sigma == beta): how often the attacker's sign estimate sigma = sgn<z0,c>
# agrees with the signer's true bimodal sign.  beta is internal to signing, so this
# builds an INSTRUMENTED COPY of the reference sources in a temp dir (one line added to
# record b_val); the reference tree itself is not modified.  Diagnostic only; the
# attack never uses beta.
#   REF=/path/to/Reference_Implementation/BiT-128 ./measure_sign_agreement.sh [nsigs]
set -e
REF="${REF:-./ref/BiT-128}"; T="${1:-20000}"
D=$(mktemp -d); mkdir "$D/ref"; cp "$REF"/*.c "$REF"/*.h "$D/ref/"; rm -f "$D/ref/KAT_SIG.c"
sed -i 's/^int bit_sig_sign(/int bit_last_b;\nint bit_sig_sign(/' "$D/ref/sign.c"
sed -i 's/        poly_cneg(&c_poly, b_val);/        poly_cneg(\&c_poly, b_val); bit_last_b = b_val;/' "$D/ref/sign.c"
grep -q 'bit_last_b = b_val' "$D/ref/sign.c" || { echo "instrumentation patch failed"; exit 1; }
gcc -O2 -no-pie -std=gnu11 -I"$D/ref" src/sign_agreement.c "$D"/ref/*.c -o "$D/sa" 2>/dev/null
"$D/sa" "$T"
