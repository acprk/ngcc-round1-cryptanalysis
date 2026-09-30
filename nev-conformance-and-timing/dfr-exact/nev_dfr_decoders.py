#!/usr/bin/env python3
"""
Exact NEV DFR union bound for BOTH decoders (spec Noise2Pt vs submitted pack.c poly_tomsg).

Derived from build/est/nev_dfr.py (same union bound, same exact 1-D convolutions, no Gaussian
anywhere).  Two things are new:

 1. per-pattern thresholds.  Spec decodes 1 iff  t_j = sum_i |d_i| < T = k(q-1)/4 = q-1   (k=4),
    so failure  <=>  sum_i |d_i| >= T  <=>  exists y in {+-1}^4 : <d,y> >= T.
    pack.c computes  t = sum_i |d_i + 1|  and decodes 1 iff t < q, so failure
      <=>  sum_i |d_i + 1| >= q  <=>  exists y : <d+1,y> >= q  <=>  exists y : <d,y> >= q - S(y)
    with S(y) = sum_i y_i in {-4,-2,0,2,4}.  Same union bound, per-pattern threshold q - S(y).

 2. memory.  The old proj_dist() materialised a (N_A, N_B, 4) int64 outer product; for B_7 that is
    50625^2*4*8 = 82 GiB (this is what killed D1).  Here we use the bilinear structure
      <A (*) B, y> = sum_i A_i * w_i(B,y),     w_i = sum_j s(i,j) y_{(i+j) mod 4} B_j
    so only the B side is enumerated (<= 50625 rows x 4 int64 = 1.6 MB); the A side enters as a
    4-fold convolution of scaled 1-D pmfs, deduplicated on the multiset {|w_i|} (valid because the
    A coefficients are i.i.d. and symmetric).  Peak memory is a few MB.

Models
------
  A  (reference; reproduces build/est/nev_dfr.out): message blocks ~ B_eta i.i.d. (the authors'
     own modelling choice, spec Sec 3.2), e' replaced by its worst case <e',y> <= k(k*eta+1)/2.
  A0 diagnostic: model A with the e' shift removed (NOT a bound, isolates the shift's cost).
  B  refined and still rigorous: message blocks carry their true parity constraint
     (sum of the 4 group coefficients == M_j mod 2, spec eq. (5)) and e' is computed *exactly*
     and *jointly* with the f'-times-m block it is correlated with.  No worst-case shift.
     B also yields max_y  -> a rigorous LOWER bound on the DFR.

Everything is a sum of non-negative quantities: no cancellation, hence no catastrophic
round-off.  See --selfcheck and the accuracy notes in NEV-review/F1-exact-dfr.md.
"""
import argparse, itertools, math, resource, sys, time
from math import comb
import numpy as np

K = 4

# ---------------------------------------------------------------- distributions
def cbd(eta):
    return {x - eta: comb(2 * eta, x) / 4.0 ** eta for x in range(2 * eta + 1)}

def tern(p):
    return {-1: p, 0: 1.0 - 2 * p, 1: p}

def tstar13(q=769, d=256):
    """Exact law of the NEV compressed-ciphertext rounding error r' (the 'T*_{1/3}' of Table 2).
    compress:   y = (341 x + 469) >> 10        (pack.c poly_compress, q=769)
    decompress: x' = (y q + 128) >> 8          (pack.c poly_decompress)
    r' = x' - x  mod+- q, for x uniform on Z_q (x = h^{-1} m is uniform)."""
    out = {}
    for x in range(q):
        yy = ((x * 341 + 469) >> 10) & (d - 1)
        xp = (yy * q + (d >> 1)) >> 8
        e = (xp - x) % q
        if e > q // 2:
            e -= q
        out[e] = out.get(e, 0.0) + 1.0 / q
    return out

def dist(code):
    if code == "T*":
        return tstar13()
    return {1: cbd(1), 2: cbd(2), 3: cbd(3), 4: cbd(4), 7: cbd(7),
            8: tern(1 / 8), 9: tern(1 / 3)}[code]

#   name : (n, q, chi_f, chi_g, chi_r, chi_e)   codes: int=B_eta, 8=T_{1/8}, 9=T_{1/3}, "T*"=rounded
SETS = {
    "C1": (512, 769, 1, 2, 9, 2), "C2": (1024, 769, 1, 8, 9, 2), "C3": (2048, 769, 8, 8, 9, 1),
    "R1": (512, 1409, 3, 3, 3, 3), "R2": (1024, 1409, 2, 2, 2, 2), "R3": (2048, 1409, 9, 9, 9, 2),
    "D1": (512, 3329, 7, 7, 7, 7), "D2": (1024, 3329, 4, 4, 4, 4), "D3": (2048, 3329, 2, 3, 2, 3),
}
ORDER = ["C1", "C2", "C3", "R1", "R2", "R3", "D1", "D2", "D3"]
CLAIM = {"C1": -160, "C2": -162, "C3": -163, "R1": -133, "R2": -158, "R3": -147,
         "D1": -136, "D2": -217, "D3": -301}
# spec-decoder per-block values from build/est/nev_dfr.out and
# build/NEV-interop/dfr/nev_dfr_all.partial.out (model A) -- the self-check targets
KNOWN_PERBLOCK = {"C1": -161.15, "C2": -143.15, "C3": -168.72,
                  "R1": -137.09, "R2": -162.87, "R3": -152.66}

# ---------------------------------------------------------------- y orbits
def yrot(y):                      # multiplication by Y in S = Z[Y]/(Y^4+1)
    return (-y[3], y[0], y[1], y[2])

def yorbits():
    """<A(*)B, y> has a law invariant under y -> +-Y^z y (A,B i.i.d. symmetric), so the 16 sign
    patterns collapse to a few orbits.  Thresholds still differ inside an orbit."""
    allys = list(itertools.product((1, -1), repeat=K))
    seen, orbs = set(), []
    for y in allys:
        if y in seen:
            continue
        orb, cur = [], y
        for _ in range(K):
            orb.append(cur); orb.append(tuple(-c for c in cur)); cur = yrot(cur)
        orb = sorted(set(orb))
        seen.update(orb); orbs.append(orb)
    assert sum(len(o) for o in orbs) == 16
    return orbs

# ---------------------------------------------------------------- exact block pmfs
def wvec(Bv, y):
    """w_i = sum_j s(i,j) y_{(i+j) mod 4} B_j, so <A (*) B, y> = sum_i A_i w_i."""
    W = np.zeros_like(Bv)
    for i in range(K):
        for j in range(K):
            m, s = i + j, 1
            if m >= K:
                m -= K; s = -1
            W[:, i] += s * y[m] * Bv[:, j]
    return W

def enum4(d):
    v = np.array(sorted(d), dtype=np.int64)
    p = np.array([d[int(x)] for x in v], dtype=np.float64)
    Bv = np.array(list(itertools.product(v, repeat=K)), dtype=np.int64)
    pv = np.prod(np.array(list(itertools.product(p, repeat=K))), axis=1)
    return Bv, pv

_ccache = {}
def conv_scaled(key, vA, pA, tag):
    """pmf of sum_i A_i * key_i  (key_i >= 0), A_i i.i.d. with values vA / probs pA."""
    ck = (tag, key)
    if ck in _ccache:
        return _ccache[ck]
    cur = np.ones(1); lo = 0
    for w in key:
        if w == 0:
            continue
        vals = vA * int(w)
        a = np.zeros(int(vals[-1] - vals[0]) + 1)
        a[(vals - vals[0]).astype(np.int64)] = pA
        cur = np.convolve(cur, a); lo += int(vals[0])
    if len(_ccache) < 400000:
        _ccache[ck] = (cur, lo)
    return cur, lo

def blockdist(dA, Bv, pBv, y, tag, shift=None):
    """Exact pmf of <A (*) B, y> (+ shift(B) if given).  A ~ dA^K i.i.d.; B enumerated."""
    vA = np.array(sorted(dA), dtype=np.int64)
    pA = np.array([dA[int(x)] for x in vA], dtype=np.float64)
    W = np.abs(wvec(Bv, y))
    W.sort(axis=1)
    if shift is None:
        keys, inv = np.unique(W, axis=0, return_inverse=True)
        shifts = np.zeros(len(keys), dtype=np.int64)
    else:
        aug = np.concatenate([W, shift.reshape(-1, 1)], axis=1)
        keys, inv = np.unique(aug, axis=0, return_inverse=True)
        shifts = keys[:, -1].copy(); keys = keys[:, :-1]
    wts = np.bincount(inv.ravel(), weights=pBv, minlength=len(keys))
    amax = int(np.abs(vA).max())
    hi = int((amax * keys.sum(axis=1) + np.abs(shifts)).max())
    out = np.zeros(2 * hi + 1); lo = -hi
    for r in range(len(keys)):
        if wts[r] == 0.0:
            continue
        cur, clo = conv_scaled(tuple(int(t) for t in keys[r]), vA, pA, tag)
        o = clo + int(shifts[r]) - lo
        out[o:o + len(cur)] += wts[r] * cur
    return out, lo

def msg_blocks(eta, parity=None):
    """4-coefficient message block: i.i.d. B_eta, optionally conditioned on sum == parity (mod 2).
    Matches spec eq. (5) / Fig. 4 exactly (verified in NEV-review/C3-samplers.md)."""
    Bv, pv = enum4(cbd(eta))
    if parity is None:
        return Bv, pv
    keep = (Bv.sum(axis=1) % 2 + 2) % 2 == parity
    Bv, pv = Bv[keep], pv[keep]
    return Bv, pv / pv.sum()

def eprime_shift(Bv, y, Mbit):
    """<e'_j, y> exactly.  e'_i = ((sum_{t<=i} m_t - sum_{t>i} m_t) - M_j)/2 (spec Sec 3.2 proof)."""
    cs = np.cumsum(Bv, axis=1)
    num = 2 * cs - cs[:, -1:] - Mbit
    assert np.all(num % 2 == 0)
    E = num // 2
    return (E * np.array(y, dtype=np.int64)).sum(axis=1)

# ---------------------------------------------------------------- convolution powers / tails
def cpow(a, lo, k):
    res, rlo = np.ones(1), 0
    b, blo = a, lo
    while k:
        if k & 1:
            res = np.convolve(res, b); rlo += blo
        k >>= 1
        if k:
            b = np.convolve(b, b); blo *= 2
    return res, rlo

def sfun(s):
    """suffix sums, accumulated from the far tail inwards (so tail entries stay accurate)."""
    return np.concatenate([np.cumsum(s[::-1])[::-1], [0.0]])

def tail2(s1, lo1, sf2, lo2, n2, c):
    """P[X1 + X2 >= c] from s1 and the precomputed suffix sums of s2."""
    idx = c - (np.arange(len(s1)) + lo1) - lo2
    np.clip(idx, 0, n2, out=idx)
    return float(np.dot(s1, sf2[idx]))

# ---------------------------------------------------------------- per-set drivers
def run_set(name, model, star=False, parity=1, override=None):
    n, q, cf, cg, cr, ce = SETS[name]
    if override:
        cf, cg, cr, ce = override
    if star:
        assert q == 769, "the rounded T*_{1/3} only exists for the q=769 (C) sets"
        cr = "T*"
    nb = n // K
    T = K * (q - 1) // 4
    eta_e = ce
    eps = K * (K * eta_e + 1) // 2           # worst-case <e',y>, = k(k eta+1)/2
    dg, dr, df = dist(cg), dist(cr), dist(cf)
    # the y-orbit reduction needs every input law to be centrally symmetric; T*_{1/3} is not
    # (it has a 2^-9.6 atom at +2), so fall back to all 16 patterns for the starred sets.
    sym = all(all(abs(d.get(-v, 0.0) - p) < 1e-15 for v, p in d.items()) for d in (dg, dr, df))
    orbits = yorbits() if sym else [[y] for y in itertools.product((1, -1), repeat=K)]
    res = {"spec": 0.0, "code": 0.0, "spec_max": 0.0, "code_max": 0.0}
    Bg, pg = enum4(dr)                       # B side of the g*r product = r
    for orb in orbits:
        y0 = orb[0]
        aG, lG = blockdist(dg, Bg, pg, y0, ("g", cg, cr))
        SG, sgl = cpow(aG, lG, nb)
        if model in ("A", "A0"):
            Be, pe = msg_blocks(eta_e)
            aF, lF = blockdist(df, Be, pe, y0, ("f", cf, ce, "plain"))
            SF, sfl = cpow(aF, lF, nb)
            sf = sfun(SF)
            shift = eps if model == "A" else 0
            for y in orb:
                S = sum(y)
                for tag, c in (("spec", T - shift), ("code", q - S - shift)):
                    p = tail2(SG, sgl, sf, sfl, len(SF), c)
                    res[tag] += p
                    res[tag + "_max"] = max(res[tag + "_max"], p)
        else:                                 # model B
            Bep, pep = msg_blocks(eta_e, parity=parity)  # M = parity^l (1^l = worst case)
            aF, lF = blockdist(df, Bep, pep, y0, ("f", cf, ce, "par%d" % parity))
            SFm, sfml = cpow(aF, lF, nb - 1)
            for y in orb:
                sh = eprime_shift(Bep, y, parity)
                a0, l0 = blockdist(df, Bep, pep, y, ("f0", cf, ce, parity, y), shift=sh)
                SF = np.convolve(SFm, a0); sfl = sfml + l0
                sf = sfun(SF)
                S = sum(y)
                for tag, c in (("spec", T), ("code", q - S)):
                    p = tail2(SG, sgl, sf, sfl, len(SF), c)
                    res[tag] += p
                    res[tag + "_max"] = max(res[tag + "_max"], p)
        del SG
    out = {"set": name, "model": model, "n": n, "q": q, "T": T, "nb": nb, "eps": eps,
           "dists": (cf, cg, cr, ce), "sym": sym, "parity": parity}
    for tag in ("spec", "code"):
        out[tag + "_block"] = math.log2(res[tag])
        out[tag + "_dfr"] = math.log2(res[tag] * nb)
        out[tag + "_lb"] = math.log2(res[tag + "_max"])
    out["delta_bits"] = out["code_block"] - out["spec_block"]
    return out

def fmt(o):
    return (f"{o['set']:>3}{'*' if o['dists'][2]=='T*' else ' '} model {o['model']:<2}  spec: block 2^{o['spec_block']:.2f} "
            f"DFR<=2^{o['spec_dfr']:.2f} | code: block 2^{o['code_block']:.2f} "
            f"DFR<=2^{o['code_dfr']:.2f} | delta(code-spec) {o['delta_bits']:+.3f} bits "
            f"| LB(max_y) spec 2^{o['spec_lb']:.2f} code 2^{o['code_lb']:.2f}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sets", nargs="*", default=ORDER)
    ap.add_argument("--model", default="A", choices=["A", "A0", "B"])
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--star", action="store_true", help="use the rounded T*_{1/3} for chi_r (C sets)")
    ap.add_argument("--parity", type=int, default=1, choices=[0, 1], help="model B: message bits")
    ap.add_argument("--dists", default=None, help="override chi_f,chi_g,chi_r,chi_e e.g. 1,8,9,1")
    a = ap.parse_args()
    for nm in a.sets:
        t0 = time.time()
        ov = None
        if a.dists:
            ov = tuple(int(x) if x != "T*" else "T*" for x in a.dists.split(","))
        o = run_set(nm, a.model, star=a.star, parity=a.parity, override=ov)
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0
        line = fmt(o) + f"  dists{o['dists']} par{o['parity']} [{time.time()-t0:.1f}s, peak RSS {rss:.0f} MiB]"
        if a.selfcheck and nm in KNOWN_PERBLOCK and a.model == "A":
            d = o["spec_block"] - KNOWN_PERBLOCK[nm]
            line += f"  SELFCHECK vs {KNOWN_PERBLOCK[nm]}: {d:+.4f} " + ("OK" if abs(d) < 0.01 else "MISMATCH")
        print(line); sys.stdout.flush()

if __name__ == "__main__":
    main()
