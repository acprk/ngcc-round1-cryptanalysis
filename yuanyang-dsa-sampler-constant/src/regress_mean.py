#!/usr/bin/env python3
"""Secret-dependence test of the YuanYang.DSA-512 signature mean, and signature-count projection.

Inputs (produced by gapstat / dumpkey):
  key<k>.txt        columns f g F G u_hat a00 a01 a10 a11 (coefficient domain)   [SCORING only]
  mu_<tag>_k<k>.txt 1024 lines: mean of (s1, s2) over N signatures (public transcript only)

Model: E[s1] = (E[x]/L) * a00 * ONE + c,  E[s2] = (E[x]/L) * (a10 + a11) * ONE + c',
with ONE = 1 + X + ... + X^(d-1). Since ONE * (1 - X) = 2 in Z[X]/(X^d + 1), we multiply the
mean by (1 - X)/2, drop the constant coefficient (absorbed by c), and regress on the true a00.
Cross-key regressions (mean of key A on a00 of key B) are the control.
Usage: regress_mean.py N key0.txt mu_A_k0.txt key7.txt mu_B_k7.txt
"""
import sys, numpy as np
D = 512; ETA = 1.026; SIG_SIG = 69.76; SIG = SIG_SIG / ETA; SLOPE_THEORY = 0.458 / 4

def mul(a, b):
    c = np.convolve(a, b); r = c[:D].copy(); r[:len(c) - D] -= c[D:]; return r
def conj(a):
    r = np.zeros(D); r[0] = a[0]; r[1:] = -a[:0:-1]; return r
INV_ONE = np.zeros(D); INV_ONE[0] = 0.5; INV_ONE[1] = -0.5   # (1 - X)/2

N = int(sys.argv[1]); args = sys.argv[2:]
keys = {args[i]: np.loadtxt(args[i]) for i in range(0, len(args), 2)}
mus = {args[i]: np.loadtxt(args[i + 1]) for i in range(0, len(args), 2)}
noise_pred = 0.35 * np.sqrt(20000 / N)
print("N=%d  (1-X)/2 * mean regressed on the stored Gram-root rows; theory slope %.4f" % (N, SLOPE_THEORY))
for mk in mus:
    y1 = mul(INV_ONE, mus[mk][:D])[1:]; y2 = mul(INV_ONE, mus[mk][D:])[1:]
    for kk in keys:
        K = keys[kk]; a00 = K[:, 5][1:]; a1011 = (K[:, 7] + K[:, 8])[1:]
        for name, y, a in [("s1 on a00", y1, a00), ("s2 on a10+a11", y2, a1011)]:
            b = a @ y / (a @ a); r = y - b * a; se = r.std() / np.sqrt(a @ a)
            tag = "OWN  " if mk == kk else "CROSS"
            print("  %s mean(%s) %-14s of %s: slope %+.4f +- %.4f  z=%+5.1f  resid rms %.3f (noise pred %.3f)"
                  % (tag, mk, name, kk, b, se, b / se, r.std(), noise_pred))
print()
print("Gram-root estimate from the public mean and projection of the signature count (simulation):")
rng = np.random.default_rng(1)
for kk in keys:
    K = keys[kk]; a00 = K[:, 5]; f, g = K[:, 0], K[:, 1]
    ah = mul(INV_ONE, mus[kk][:D]) / SLOPE_THEORY; ah[0] = a00[0]
    err = np.sqrt(np.mean((ah - a00)[1:] ** 2))
    u = mul(f, conj(f)) + mul(g, conj(g))
    chk = (SIG ** 2 - 1) * np.eye(1, D, 0)[0] - mul(a00, conj(a00))
    print("  %s: a00 coefficient error %.3f (432/sqrt(N) = %.3f); sigma^2-1-a00*conj(a00) vs f fbar + g gbar: max dev %.2e"
          % (kk, err, 432 / np.sqrt(N), np.abs(chk - u).max()))
    for Nt in [1e8, 1e9, 1e10, 3e10, 1e11]:
        s = err * np.sqrt(N / Nt); e = rng.normal(0, s, D); e[0] = 0
        est = (SIG ** 2 - 1) * np.eye(1, D, 0)[0] - mul(a00 + e, conj(a00 + e))
        wrong = int(np.sum(np.abs(est - u) > 0.5))
        print("     N=%.0e: a00 err %.4f -> f fbar + g gbar coefficient err rms %.3f, wrong after rounding %d/512" % (Nt, s, (est - u)[1:].std(), wrong))
