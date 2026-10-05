#!/usr/bin/env python3
"""Exact challenge-set sizes for MORNING-ATLAS.
Spec (Sec. 2.7 / Table 2): |ChSet| = C(n, kappa) * 2^kappa, and kappa is chosen so that
|ChSet| exceeds the targeted security level.  The shipped challenge() draws each position with
one byte (b = outbuf[pos++], accepted while b <= i), so for n = 512 a non-zero coefficient can only
land in [0,256) or be moved by the swap into [n-kappa, n): at most 256 + kappa positions."""
from math import comb, log2
SETS = [  # name, claimed classical bits, n, kappa (spec Table 2), kappa in the shipped code
    ("ATLAS-128", 128, 128, 31, 31),
    ("ATLAS-192", 192, 128, 69, 64),
    ("ATLAS-256", 256, 256, 60, 60),
    ("ATLAS-512", 512, 512, 60, 60),
]
lg = lambda n, k: log2(comb(n, k)) + k
print(f"{'set':10} {'claim':>5} {'n':>4} {'kappa':>5}  {'spec |ChSet|':>12}  {'code image <=':>13}  verdict")
for name, lam, n, ks, kc in SETS:
    spec = lg(n, ks)
    reach = min(n, 256 + kc) if n > 256 else n
    code = lg(reach, kc)
    v = []
    if spec < lam: v.append(f"SPEC below claim by {lam-spec:.1f} bits")
    if code < lam: v.append(f"CODE below claim by {lam-code:.1f} bits")
    print(f"{name:10} {lam:5} {n:4} {ks:3}/{kc:<2} 2^{spec:9.2f}  2^{code:10.2f}  {'; '.join(v) or 'ok'}")
k = next(k for k in range(60, 512) if lg(512, k) >= 512)
print(f"\nsmallest kappa with C(512,kappa)*2^kappa >= 2^512: kappa = {k} (2^{lg(512,k):.2f}); "
      f"for comparison Aigis-Sig+ PARAMS III (n=512) uses tau = 118 (2^{lg(512,118):.2f})")
