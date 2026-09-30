#!/usr/bin/env python3
"""DFR model checks for Scloud+ (spec Sec. 3.1.4, Table 16).

A  spec model: iid continuous Gaussian coords, Var = 4(m+n)rs re(1-rs)(1-re)+2re(1-re),
   block fails iff ||eps|| > R=(q/g) r  ->  Gamma(d/2, R^2/(2 s2))/Gamma(d/2)
B  exact-PMF iid model: each coordinate has the EXACT distribution of
   sum_{t<m+n} (BD_s * BD_e) + BD_e  (binomial mixture, log domain), d coords iid;
   tail of sum of squares via exponentially tilted FFT convolution (exact up to fp).
C  key-conditional Gaussian model: given (S,E), each row of the noise matrix is
   N(0, Sigma) with Sigma = Vs E^T E + Ve S^T S + Ve I (captures key variation AND
   within-row correlation from the shared S'_i, E1_i); rows independent given key.
   Tail of the block quadratic form by Lugannani-Rice saddlepoint; averaged over
   random keys drawn from the spec BD distribution.
Outputs log2 DFR for each model.
"""
import numpy as np, math, sys
from scipy.special import gammaln, logsumexp, erfcx, gammaincc
import mpmath as mp

SETS = [  # name, m=n, mbar, nbar, rs, re, lattice, d, g, blocks, lambda, table16
    ("128", 608, 8, 8, 1/4, 1/2, "BW", 32, 8, 2, 128, -138.5),
    ("192", 832, 12, 11, 1/2, 1/2, "BW", 128, 8, 1, 192, -220.9),
    ("256", 1184, 12, 11, 1/6, 1/6, "RBW", 128, 16, 1, 256, -271.8),
    ("384", 1664, 16, 16, 1/6, 1/6, "BW", 128, 8, 2, 384, -457.7),
    ("512", 2400, 16, 16, 1/12, 1/12, "RBW", 128, 16, 2, 512, -552.6),
]
q = 1024
LN2 = math.log(2)

def spec_model(n, rs, re, lat, d, g, blocks):
    s2 = 4 * (2 * n) * rs * re * (1 - rs) * (1 - re) + 2 * re * (1 - re)
    r = math.sqrt(d / 8) if lat == "BW" else math.sqrt(d / 4)
    R = q / g * r
    p = mp.gammainc(mp.mpf(d) / 2, mp.mpf(R) ** 2 / (2 * s2), mp.inf, regularized=True)
    return s2, R, float(mp.log(blocks * p, 2)), float(mp.log(p, 2))

def coord_pmf(n, rs, re, xmax):
    """exact log-pmf of X = sum_{t<2n} Y_t + Z, Y_t=+-1 wp p/2 each, p=Vs*Ve; Z~BD_e"""
    Vs, Ve = 2 * rs * (1 - rs), 2 * re * (1 - re)
    N, p = 2 * n, Vs * Ve
    ks = np.arange(N + 1)
    logK = gammaln(N + 1) - gammaln(ks + 1) - gammaln(N - ks + 1) + ks * math.log(p) + (N - ks) * math.log1p(-p)
    xs = np.arange(-xmax, xmax + 1)
    out = np.full(xs.shape, -np.inf)
    for k in ks:
        if logK[k] < -1500: continue
        # sum = 2j - k, j ~ Bin(k, 1/2)
        lo = max(-k, -xmax); hi = min(k, xmax)
        if lo > hi: continue
        x = np.arange(lo, hi + 1)
        x = x[(x + k) % 2 == 0]
        j = (x + k) // 2
        lw = logK[k] + gammaln(k + 1) - gammaln(j + 1) - gammaln(k - j + 1) - k * LN2
        idx = x + xmax
        out[idx] = np.logaddexp(out[idx], lw)
    # convolve with BD_e : P(+-1)=re(1-re), P(0)=1-2re(1-re)
    pz = {-1: math.log(re * (1 - re)), 0: math.log(1 - 2 * re * (1 - re)), 1: math.log(re * (1 - re))}
    res = np.full(xs.shape, -np.inf)
    for z, lz in pz.items():
        sh = np.full(xs.shape, -np.inf)
        if z == 1: sh[1:] = out[:-1]
        elif z == -1: sh[:-1] = out[1:]
        else: sh = out.copy()
        res = np.logaddexp(res, sh + lz)
    return xs, res

def exact_iid_tail(xs, logp, d, R2):
    """log P(sum_{i<d} X_i^2 >= R2) for iid X with log-pmf logp on xs; tilted FFT convolution."""
    y = xs.astype(np.int64) ** 2
    ymax = int(1.6 * R2) + 1
    # log-pmf of Y = X^2 on 0..ymax
    ly = np.full(ymax + 1, -np.inf)
    mask = y <= ymax
    np.logaddexp.at(ly, y[mask], logp[mask])
    lost_single = logsumexp(logp[~mask]) if (~mask).any() else -np.inf
    grid = np.arange(ymax + 1)
    fin = np.isfinite(ly)
    # find tilt s with d * E_s[Y] = R2
    def meanY(s):
        lw = ly[fin] + s * grid[fin]
        lM = logsumexp(lw)
        return math.exp(logsumexp(lw + np.log(grid[fin] + 1e-300)) - lM), lM
    lo, hi = 0.0, 0.05
    while meanY(hi)[0] * d < R2: hi *= 2
    for _ in range(200):
        mid = (lo + hi) / 2
        if meanY(mid)[0] * d < R2: lo = mid
        else: hi = mid
    s = (lo + hi) / 2
    _, lM = meanY(s)
    tilt = np.zeros(ymax + 1)
    tilt[fin] = np.exp(ly[fin] + s * grid[fin] - lM)
    # d-fold convolution (d power of 2) by repeated squaring, truncated at ymax
    cur = tilt
    k = 1
    while k < d:
        L = 1 << int(math.ceil(math.log2(2 * len(cur))))
        f = np.fft.rfft(cur, L)
        cur = np.fft.irfft(f * f, L)[: ymax + 1]
        cur[cur < 0] = 0
        k *= 2
    idx = np.arange(int(math.ceil(R2)), ymax + 1)
    tail = np.sum(cur[idx] * np.exp(-s * (idx - R2)))
    ltail = d * lM - s * R2 + math.log(tail)
    return ltail / LN2, s, lost_single / LN2

def lr_tail(lams, x):
    """Lugannani-Rice approx of log P(sum lam_l chi2_1 >= x); returns natural log."""
    lams = np.asarray(lams, float)
    K = lambda s: -0.5 * np.sum(np.log1p(-2 * s * lams))
    K1 = lambda s: np.sum(lams / (1 - 2 * s * lams))
    K2 = lambda s: np.sum(2 * lams ** 2 / (1 - 2 * s * lams) ** 2)
    lo, hi = 0.0, 0.5 / lams.max() * (1 - 1e-15)
    for _ in range(200):
        mid = (lo + hi) / 2
        if K1(mid) < x: lo = mid
        else: hi = mid
    s = (lo + hi) / 2
    w = math.sqrt(2 * (s * x - K(s)))
    u = s * math.sqrt(K2(s))
    # P = phi(w) [ Mills(w) + 1/u - 1/w ],  Mills(w)=(1-Phi(w))/phi(w)=sqrt(pi/2) erfcx(w/sqrt2)
    logphi = -0.5 * w * w - 0.5 * math.log(2 * math.pi)
    br = math.sqrt(math.pi / 2) * erfcx(w / math.sqrt(2)) + 1 / u - 1 / w
    return logphi + math.log(br)

def bd(rng, rho, shape):
    a = rng.random(shape) < rho
    b = rng.random(shape) < rho
    return a.astype(np.int8) - b.astype(np.int8)

def key_model(n, mbar, nbar, rs, re, d, blocks, R2, nkeys, rng):
    Vs, Ve = 2 * rs * (1 - rs), 2 * re * (1 - re)
    # block -> rows -> columns
    blk_rows = []
    for b in range(blocks):
        rows = {}
        for p in range(b * d, (b + 1) * d):
            rows.setdefault(p // nbar, []).append(p % nbar)
        blk_rows.append(list(rows.values()))
    logs = []
    diag_only = []
    for _ in range(nkeys):
        S = bd(rng, rs, (n, nbar)).astype(float)
        E = bd(rng, re, (n, nbar)).astype(float)
        Sig = Vs * E.T @ E + Ve * S.T @ S + Ve * np.eye(nbar)
        tot = []; totd = []
        for b in range(blocks):
            lams = []; lamd = []
            for cols in blk_rows[b]:
                sub = Sig[np.ix_(cols, cols)]
                lams += list(np.linalg.eigvalsh(sub))
                lamd += list(np.diag(sub))
            tot.append(lr_tail(lams, R2)); totd.append(lr_tail(lamd, R2))
        logs.append(logsumexp(tot)); diag_only.append(logsumexp(totd))
    logs = np.array(logs) / LN2; diag_only = np.array(diag_only) / LN2
    mean = (logsumexp(logs * LN2) - math.log(nkeys)) / LN2
    meand = (logsumexp(diag_only * LN2) - math.log(nkeys)) / LN2
    return mean, np.median(logs), np.percentile(logs, [1, 99]), meand

if __name__ == "__main__":
    nkeys = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    rng = np.random.default_rng(20260930)
    print("| L | sigma^2 | R | A: spec Gamma (Table16) | A': LR-saddlepoint iid (check) | B: exact-PMF iid | B-A | C: key-cond. Gaussian, mean over keys | C-A | C diag-only (key var. only) | C median [1%,99%] | lambda |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for (name, n, mbar, nbar, rs, re, lat, d, g, blocks, lam, t16) in SETS:
        s2, R, A, Ablk = spec_model(n, rs, re, lat, d, g, blocks)
        R2 = R * R
        Aprime = (lr_tail([s2] * d, R2) + math.log(blocks)) / LN2
        xmax = int(R) + 60
        xs, lp = coord_pmf(n, rs, re, xmax)
        var_exact = float(np.sum(np.exp(lp) * xs.astype(float) ** 2))
        B, s, lost = exact_iid_tail(xs, lp, d, R2)
        B += math.log2(blocks)
        C, Cmed, Cpct, Cd = key_model(n, mbar, nbar, rs, re, d, blocks, R2, nkeys, rng)
        print(f"| {name} | {s2:.3f} (exact pmf {var_exact:.3f}) | {R:.2f} | {A:.2f} (T16 {t16}) | {Aprime:.2f} | {B:.2f} | {B - A:+.2f} | {C:.2f} | {C - A:+.2f} | {Cd:.2f} | {Cmed:.2f} [{Cpct[0]:.2f},{Cpct[1]:.2f}] | {lam} |", flush=True)
