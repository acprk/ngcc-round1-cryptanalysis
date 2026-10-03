#!/usr/bin/env python3
"""[cal] The unmodified doom.py reproduces the two rows ngcc.dev published for kem-05-2 (BIKE-MLThre)."""
from doom import dsDOOM
for name, r, w, q, ref in [("BIKE-MLThre-128", 12323, 134, 69, "127.890 / 96.189"),
                           ("BIKE-MLThre-256", 40973, 264, 73, "255.780 / 103.648")]:
    t, m, _ = dsDOOM(2 * r, r - 1, w, r * (1 << q))
    print(f"  {name} SD[{2*r},{r-1},{w}] rot={r} Q=2^{q}: T=2^{t:.3f} mem=2^{m:.3f}   ngcc.dev kem-05-2: {ref}")
