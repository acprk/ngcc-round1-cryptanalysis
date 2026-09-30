#!/usr/bin/env sage -python
"""
Cross-check of the i.i.d. finding with the *stock* estimator only.

For a fixed total secret weight h the stock sparse dual hybrid lwe_dual.dual_hybrid on
SparseTernary(h/2, h/2, n) gives the cost T(h) of attacking a key of weight h with probability 0.99.
Under the real i.i.d. BD_p key distribution, weight h occurs with probability
Pr[W = h], W ~ Binomial(n, d), d = 2r(1-r). A cost/advantage (T/eps) adversary that only attacks keys of
weight <= h achieves  log2 T(h) - log2 Pr[W <= h].
We also report the same for the ciphertext secret S' (identical dimension/distribution here).

Usage: nice -n 10 sage -python weak_key_scan.py LEVEL CM HMIN HMAX HSTEP [ejk|matzov]
  ejk    = lwe_dual.dual_hybrid (sparse-aware EJK20, default)
  matzov = LWE.dual_hybrid (MATZOV22 dual-sieve-FFT; uses only the secret stddev sqrt(h/n))
  primal = LWE.primal_hybrid(mitm=False, babai=False)  (bdd_hybrid; not subject to the dual-attack heuristic debate)
  usvp   = LWE.primal_usvp
"""
import sys, json, time
import os
sys.path.insert(0, os.environ.get('ESTIMATOR', os.path.expanduser('~/lattice-estimator')))
from sage.all import RR, QQ, log, binomial
from estimator import LWE
from estimator import lwe_dual
from estimator.nd import SparseTernary
from scloud_est import instance, COST_MODELS, PARAMS, Q

R = __import__("sage.all", fromlist=["RealField"]).RealField(200)
L, cmn = int(sys.argv[1]), sys.argv[2]
hmin, hmax, hstep = map(int, sys.argv[3:6])
ATT = sys.argv[6] if len(sys.argv) > 6 else "ejk"
Pp = PARAMS[L]
base = instance(L, "ct", "fw")
n = base.n
r = QQ(1) / Pp["ps"]
d = R(2 * r * (1 - r))
def logpmf(w):
    return float(log(R(binomial(n, w)) * d ** w * (1 - d) ** (n - w), 2))
def logcdf(w):
    return float(log(sum(R(binomial(n, k)) * d ** k * (1 - d) ** (n - k) for k in range(0, w + 1)), 2))
print(json.dumps(dict(level=L, expected_weight=float(n * d), sd=float((n * d * (1 - d)).sqrt()))), flush=True)
for h in range(hmin, hmax + 1, hstep):
    t0 = time.time()
    P = base.updated(Xs=SparseTernary(h // 2, h - h // 2, n))
    if ATT == "ejk":
        c = lwe_dual.dual_hybrid(P, red_cost_model=COST_MODELS[cmn])
    elif ATT == "primal":
        c = LWE.primal_hybrid(P, mitm=False, babai=False, red_cost_model=COST_MODELS[cmn])
    elif ATT == "usvp":
        c = LWE.primal_usvp(P, red_cost_model=COST_MODELS[cmn])
    else:
        c = LWE.dual_hybrid(P, red_cost_model=COST_MODELS[cmn])
    lc = float(log(c["rop"], 2))
    print(json.dumps(dict(level=L, cm=cmn, att=ATT, h=h, log2T=lc, log2P_eq=logpmf(h), log2P_le=logcdf(h),
                          T_over_eps=lc - logcdf(h), beta=int(c["beta"]), zeta=int(c.get("zeta", 0) or 0),
                          h1=int(c.get("h1", -1)), secs=round(time.time() - t0, 1))), flush=True)
