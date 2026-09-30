#!/usr/bin/env python3
"""Verification harness for nev_dfr_decoders.py.

V1  blockdist() vs an independent brute-force implementation of the same block pmf
    (the (N_A,N_B,4) outer product of build/est/nev_dfr.py, chunked so it fits).
V2  tail2() (survival-function dot product) vs a direct np.convolve + boolean-mask sum.
V3  the whole nb-fold convolution chain redone in np.longdouble (64-bit mantissa) --
    this is the only stage where float64 round-off can accumulate.
V4  eprime_shift() vs a direct polynomial computation of e' = vbar*(m-mbar)/2 in R_q.
"""
import itertools, math, sys
import numpy as np
import nev_dfr_decoders as M

K = 4
ok = True

def rep(tag, good, detail=""):
    global ok
    ok &= good
    print(f"[{'PASS' if good else 'FAIL'}] {tag} {detail}")

# ---------------------------------------------------------------- V1
def brute_block(dA, dB, y):
    """build/est/nev_dfr.py proj_dist(), chunked over A."""
    vA = np.array(sorted(dA)); pA = np.array([dA[int(v)] for v in vA])
    vB = np.array(sorted(dB)); pB = np.array([dB[int(v)] for v in vB])
    A = np.array(list(itertools.product(vA, repeat=K)), dtype=np.int64)
    PA = np.prod(np.array(list(itertools.product(pA, repeat=K))), axis=1)
    B = np.array(list(itertools.product(vB, repeat=K)), dtype=np.int64)
    PB = np.prod(np.array(list(itertools.product(pB, repeat=K))), axis=1)
    hi = int(np.abs(vA).max() * K * np.abs(vB).max() * K)
    out = np.zeros(2 * hi + 1)
    step = max(1, 20000000 // max(1, len(B)))
    for s in range(0, len(A), step):
        Ac = A[s:s + step]
        C = np.zeros((Ac.shape[0], B.shape[0], K), dtype=np.int64)
        for i in range(K):
            for j in range(K):
                m, sg = i + j, 1
                if m >= K:
                    m -= K; sg = -1
                C[:, :, m] += sg * np.outer(Ac[:, i], B[:, j])
        X = (C * np.array(y)).sum(axis=2).ravel()
        W = np.outer(PA[s:s + step], PB).ravel()
        out += np.bincount(X + hi, weights=W, minlength=2 * hi + 1)
    return out, -hi

for (ca, cb, y) in [(1, 2, (1, -1, 1, 1)), (2, 9, (1, 1, -1, -1)), (3, 3, (-1, 1, 1, 1)),
                    (8, 9, (1, 1, 1, 1)), (4, 4, (1, -1, -1, 1))]:
    dA, dB = M.dist(ca), M.dist(cb)
    Bv, pv = M.enum4(dB)
    a1, l1 = M.blockdist(dA, Bv, pv, y, ("v", ca, cb))
    a2, l2 = brute_block(dA, dB, y)
    n = max(len(a1) + l1, len(a2) + l2) - min(l1, l2)
    lo = min(l1, l2)
    x1 = np.zeros(n); x1[l1 - lo:l1 - lo + len(a1)] = a1
    x2 = np.zeros(n); x2[l2 - lo:l2 - lo + len(a2)] = a2
    err = np.abs(x1 - x2).max()
    # tolerance 1e-13: the *reference* accumulates up to 2.6e9 products per bin in float64 and
    # loses ~1e-15 of total mass; blockdist keeps mass at exactly 1.0.
    rep(f"V1 blockdist vs brute force chi=({ca},{cb}) y={y}", err < 1e-13,
        f"max abs diff {err:.3e}, mass {x1.sum():.15f}/{x2.sum():.15f}")

# ---------------------------------------------------------------- V2
rng = np.random.default_rng(7)
s1 = rng.random(400); s1 /= s1.sum(); l1 = -173
s2 = rng.random(311); s2 /= s2.sum(); l2 = 42
full = np.convolve(s1, s2); lof = l1 + l2
sf2 = M.sfun(s2)
worst = 0.0
for c in range(lof - 5, lof + len(full) + 5):
    direct = full[(np.arange(len(full)) + lof) >= c].sum()
    fast = M.tail2(s1, l1, sf2, l2, len(s2), c)
    worst = max(worst, abs(direct - fast))
rep("V2 tail2 vs direct convolve+mask", worst < 1e-14, f"max abs diff {worst:.3e}")

# ---------------------------------------------------------------- V3
def longdouble_chain(name, model="A"):
    n, q, cf, cg, cr, ce = M.SETS[name]
    nb = n // K; T = K * (q - 1) // 4
    eps = K * (K * ce + 1) // 2 if model == "A" else 0
    dg, dr, df = M.dist(cg), M.dist(cr), M.dist(cf)
    Bg, pg = M.enum4(dr)
    Be, pe = M.msg_blocks(ce)
    tot64 = tot80 = 0.0
    for orb in M.yorbits():
        y0 = orb[0]
        aG, lG = M.blockdist(dg, Bg, pg, y0, ("Vg", cg, cr))
        aF, lF = M.blockdist(df, Be, pe, y0, ("Vf", cf, ce))
        for dt in (np.float64, np.longdouble):
            g = aG.astype(dt); f = aF.astype(dt)
            SG, sgl = M.cpow(g, lG, nb)
            SF, sfl = M.cpow(f, lF, nb)
            sf = np.concatenate([np.cumsum(SF[::-1])[::-1], np.zeros(1, dtype=dt)])
            for y in orb:
                idx = np.clip((T - eps) - (np.arange(len(SG)) + sgl) - sfl, 0, len(SF))
                p = float(np.dot(SG, sf[idx]))
                if dt is np.float64:
                    tot64 += p
                else:
                    tot80 += p
    return math.log2(tot64), math.log2(tot80)

for nm in ("C2", "R1", "D1"):
    a, b = longdouble_chain(nm)
    rep(f"V3 float64 vs longdouble chain, {nm} model A", abs(a - b) < 1e-6,
        f"float64 2^{a:.6f} longdouble 2^{b:.6f} diff {abs(a-b):.2e} bits")

# ---------------------------------------------------------------- V4
def brute_eprime(n, q, mblock, Mbit, gidx, y):
    """e' = vbar*(m - mbar)/2 computed in R_q = Z[x]/(x^n+1) with vbar = sum_t x^{t n/k}."""
    nk = n // K
    m = np.zeros(n, dtype=np.int64); mb = np.zeros(n, dtype=np.int64)
    m[[gidx + t * nk for t in range(K)]] = mblock
    mb[gidx] = Mbit
    d = m - mb
    vbar = np.zeros(n, dtype=np.int64)
    for t in range(K):
        vbar[t * nk] = 1
    c = np.zeros(2 * n, dtype=np.int64)
    for i in np.nonzero(vbar)[0]:
        c[i:i + n] += vbar[i] * d
    prod = c[:n] - c[n:]
    e = prod[[gidx + t * nk for t in range(K)]]
    assert np.all(e % 2 == 0)
    return int((e // 2 * np.array(y)).sum())

rngq = np.random.default_rng(11)
bad = 0
for trial in range(300):
    eta = int(rngq.integers(1, 5)); Mbit = int(rngq.integers(0, 2))
    Bv, pv = M.msg_blocks(eta, parity=Mbit)
    r = int(rngq.integers(0, len(Bv)))
    y = tuple(int(t) for t in rngq.choice([1, -1], size=K))
    got = int(M.eprime_shift(Bv[r:r + 1], y, Mbit)[0])
    want = brute_eprime(512, 769, Bv[r], Mbit, int(rngq.integers(0, 128)), y)
    bad += (got != want)
rep("V4 eprime_shift vs polynomial vbar*(m-mbar)/2", bad == 0, f"{bad}/300 mismatches")

# e' infinity-norm bound k*eta+1)/2 and hence <e',y> <= k(k*eta+1)/2
worst = {}
for eta in (1, 2, 3, 4, 7):
    for Mbit in (0, 1):
        Bv, pv = M.msg_blocks(eta, parity=Mbit)
        cs = np.cumsum(Bv, axis=1)
        E = (2 * cs - cs[:, -1:] - Mbit) // 2
        worst[(eta, Mbit)] = (int(np.abs(E).max()), (K * eta + 1) // 2 + ((K * eta + 1) % 2))
        mx = 0
        for y in itertools.product((1, -1), repeat=K):
            mx = max(mx, int(M.eprime_shift(Bv, y, Mbit).max()))
        rep(f"V4b <e',y> <= k(k*eta+1)/2 for eta={eta} M={Mbit}", mx <= K * (K * eta + 1) // 2,
            f"observed max {mx} <= {K*(K*eta+1)//2}")

print("\nALL CHECKS PASS" if ok else "\nSOME CHECKS FAILED")
sys.exit(0 if ok else 1)
