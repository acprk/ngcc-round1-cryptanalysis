#!/usr/bin/env python3
"""Summarise probe output: is the eta re-expansion trace secret-dependent, repeatable, and eta-correlated?"""
import csv, sys, statistics as st
def corr(a, b):
    ma, mb = st.mean(a), st.mean(b)
    va = sum((x - ma) ** 2 for x in a); vb = sum((y - mb) ** 2 for y in b)
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / (va * vb) ** .5
L, path = sys.argv[1], sys.argv[2]
r = list(csv.DictReader(open(path)))
rej = [int(x['rejections']) for x in r]
rep = sum(x['draws_eta'] == x['draws_eta_repeat'] for x in r)
se = [int(x['sum_eta']) for x in r]; c0 = [int(x['count0']) for x in r]
n = len(r); thr = 1.96 / n ** .5
print(f"  QingLuan-{L}: keys={n}  rejections min/mean/max = {min(rej)}/{st.mean(rej):.1f}/{max(rej)}  "
      f"distinct values={len(set(rej))}  identical on re-expansion: {rep}/{n}")
print(f"     corr(rejections, sum eta) = {corr(rej, se):+.4f}   corr(rejections, #eta==0) = {corr(rej, c0):+.4f}"
      f"   (5% significance threshold |r| > {thr:.3f})")
