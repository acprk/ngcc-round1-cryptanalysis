#!/usr/bin/env python3
"""HARE same-key DS-DOOM cost with the UNMODIFIED official estimator of May & Sa Diogo,
ePrint 2026/517 (github.com/Gabsadio/Multi-Instance-KEM, doom.py @ 39b78dcc) -- the same file and
commit that reproduces ngcc.dev kem-05-2 bit-for-bit (see [cal] in run_all.sh).

Instance per ciphertext (vendor ref/hqc.c): u = r1 + h*r2 mod X^n-1, |r1| = |r2| = wr, h fixed by pk
  -> SD[2n, k, 2wr] with Q same-key targets and n cyclic shifts each (rot = n), i.e. M = n*Q.
We use k = n-2 (as for TriQ-KEM) and print k = n, n-1 as a sensitivity check.

usage: hare_dsdoom.py REFROOT_IMPL Qlist        (n, wr read from the vendor parameters.h)
"""
import sys, os, re
from doom import dsDOOM

def vendor_params(impl):
    out = {}
    for lvl, alias, tgt in [(128, "HARE-2", 128), (256, "HARE-5", 256), (384, "HARE-7", 384), (512, "HARE-9", 512)]:
        f = os.path.join(impl, "Reference_Implementation", f"HARE-{lvl}", "kr", "parameters.h")
        txt = open(f).read()
        n = int(re.search(r"#define PARAM_N\s+(\d+)", txt).group(1))
        wr = int(re.search(r"#define PARAM_OMEGA_R\s+(\d+)", txt).group(1))
        out[f"HARE-{lvl} ({alias})"] = (n, wr, tgt)
    return out

impl, qs = sys.argv[1], [int(x) for x in sys.argv[2].split(",")]
sets = vendor_params(impl)
# spec Table 2 only -- NOT in the submitted implementation package (README: only HARE-2/5/7/9 shipped)
sets["HARE-1 (spec only)"] = (16067, 66, 128)
sets["HARE-3 (spec only)"] = (32653, 100, 192)

for name, (n, wr, tgt) in sets.items():
    first = None
    print(f"--- {name}: n={n} wr={wr} SD[{2*n},{n-2},{2*wr}] rot=n claimed={tgt}")
    for q in qs:
        t, m, _ = dsDOOM(2 * n, n - 2, 2 * wr, n * (1 << q))
        below = t < tgt
        if below and first is None: first = q
        print(f"  Q=2^{q:<2d} T=2^{t:8.3f}  mem=2^{m:7.3f}  {'BELOW claimed' if below else ''}", flush=True)
    sens = [dsDOOM(2 * n, k, 2 * wr, n * (1 << qs[-1]))[0] for k in (n, n - 1, n - 2)]
    print(f"  k-sensitivity @Q=2^{qs[-1]}: k=n {sens[0]:.3f}  k=n-1 {sens[1]:.3f}  k=n-2 {sens[2]:.3f}")
    print(f"  => first Q below claimed: {'2^%d' % first if first is not None else 'none up to 2^%d' % qs[-1]}")
