"""Failure-boosting cost for the submitted WeaverKEM-256 (Weaver-1024, no high-layer BCH decode).
The attacker picks random FO messages m, derives r = G(m||H(pk)) offline, and only submits ciphertexts whose
||r||^2 >= R0. Only the r-norm is used (the attacker also knows c_u, c_v and r's exact shape; ignoring them makes
this an upper bound on attacker cost). Per-query failure probability = 220 * p_hi(R0, S) (union over the 220
payload bits, which are not error-corrected in the submitted code). Uses the conditional grid from model.py."""
import json, numpy as np, sys
from math import comb, log2
from scipy.interpolate import RegularGridInterpolator
import model
name = sys.argv[1] if len(sys.argv) > 1 else 'W1024'
M = json.load(open(f'logs/model_{name}.json'))
P = model.SETS[name]; kn = P['k'] * P['n']
rv, rp = model.cbd(P['eta2']); sv, sp = model.cbd(P['eta1'])
def norm_dist(v, p):
    sq = np.zeros(v.max() ** 2 + 1); np.add.at(sq, v ** 2, p)
    out = None; e = kn; base = sq
    while e:
        if e & 1: out = base if out is None else np.convolve(out, base)
        e >>= 1
        if e: base = np.convolve(base, base)
    return out
NR = norm_dist(rv, rp); NS = norm_dist(sv, sp)
sfR = np.cumsum(NR[::-1])[::-1]
Rp = np.array(M['grid_R'], float); Sp = np.array(M['grid_S'], float); LPH = np.array(M['LPH'])
f = RegularGridInterpolator((Rp, Sp), LPH, bounds_error=False, fill_value=None)
Smed = int(np.searchsorted(np.cumsum(NS), 0.5))
Si = np.nonzero(NS > NS.max() * 1e-60)[0]
npay = P['hi'][1]
print(f'{name}: payload bits without BCH = {npay}; median ||s||^2 = {Smed}; E||r||^2 = {kn*(rv**2*rp).sum():.0f}')
print(' log2 P_sel(R>=R0) | R0 | log2 per-query DFR (median key) | log2 per-query DFR (avg key) | log2 queries | log2 precomp')
rows = []
for k in [0, 5, 10, 20, 30, 40, 50, 60, 80, 100]:
    if k == 0:
        R0 = int(np.searchsorted(np.cumsum(NR), 0.5)); lsel = -1.0
    else:
        idx = np.nonzero(sfR >= 2.0 ** (-k))[0]
        if not len(idx): continue
        R0 = int(idx[-1]); lsel = log2(sfR[R0])
    lmed = float(f([[R0, Smed]])[0]) + log2(npay)
    lavg = np.log2((NS[Si] * np.exp2(f(np.c_[np.full(len(Si), R0), Si]))).sum()) + log2(npay)
    q = -lavg; pre = q - lsel
    rows.append((lsel, R0, lmed, lavg, q, pre))
    print(f'  {lsel:7.1f} | {R0:6d} | {lmed:7.1f} | {lavg:7.1f} | {q:6.1f} | {pre:6.1f}')
json.dump(rows, open(f'logs/boost_{name}.json', 'w'))
