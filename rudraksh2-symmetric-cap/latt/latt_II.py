#!/usr/bin/env python3
# Independent lattice-estimator recompute of the Rudraksh2-II parameter sets
# (which ship no implementation), against an ML-KEM-512 anchor produced by the
# same script/models. Primary/dual key-recovery, exact CBD distributions.
#
#   LATTICE_ESTIMATOR=/path/to/lattice-estimator sage -python latt_II.py
#
# Result: 128-II is 4.5-6.4 bits below the ML-KEM-512 (NIST L1) anchor in every
# model; the authors' own Table 14 CSVP for 128-II is 2^114.
import os, sys
sys.path.insert(0, os.environ.get("LATTICE_ESTIMATOR", "/home/luck/xzy/lattice-estimator"))
from estimator import *
from sage.all import log
from estimator.nd import CenteredBinomial as CB

def bits(r):
    try:    return f"2^{float(log(r['rop'],2)):.1f} (beta={r.get('beta','?')})"
    except Exception: return str(r)

def run(tag, P):
    print("####", tag, flush=True)
    for name, fn in [("usvp", LWE.primal_usvp), ("bdd", LWE.primal_bdd),
                     ("dual_hybrid", LWE.dual_hybrid)]:
        for cm, lab in [(RC.MATZOV, "MATZOV"), (RC.ADPS16, "CoreSVP")]:
            try:    print(f"  {name:12s} {lab:8s} {bits(fn(P, red_cost_model=cm))}", flush=True)
            except Exception as e: print(f"  {name:12s} {lab:8s} ERR {repr(e)[:70]}", flush=True)

# module dim = l*n, m = l*n samples, q per Table 1
run("ML-KEM-512 anchor (n=512,q=3329,eta=3)",
    LWE.Parameters(n=512, q=3329, Xs=CB(3), Xe=CB(3), m=512))
run("Rudraksh2-128-II (l=9,n=64,q=4001,eta=1) dim=576",
    LWE.Parameters(n=576, q=4001, Xs=CB(1), Xe=CB(1), m=576))
run("Rudraksh2-256-II (l=9,n=128,q=4001,eta=1) dim=1152",
    LWE.Parameters(n=1152, q=4001, Xs=CB(1), Xe=CB(1), m=1152))
run("Rudraksh2-512-II (l=9,n=256,q=4001,eta=1) dim=2304",
    LWE.Parameters(n=2304, q=4001, Xs=CB(1), Xe=CB(1), m=2304))
