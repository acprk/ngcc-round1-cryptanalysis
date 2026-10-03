# Item 1: spec Algorithm 9 (weak-key test) as written accumulates sum(mu^2); the code, App. A and
# Tables 11-14 use sum(C(mu,2)). Reads r, d, s, s' from the submitted trike_params.h.
#   python3 alg9.py <REFDIR>   (REFDIR = .../Reference_Implementation)
# Lower bounds: d positions give C(d,2) intra-block distances, so sum(mu) = C(d,2) and
# sum(mu^2) >= sum(mu); inter-block gives d^2 differences, so sum(c^2) >= d^2.
# Also draws random keys and evaluates both readings literally (folded intra distance, as in sample.c).
import re, sys, random
from math import comb
ref = sys.argv[1]
print(f"{'set':8} {'d':>4} {'C(d,2)':>7} {'s':>5} {'d^2':>6} {'s1':>5} | literal sum(mu^2) rejects | binomial rejects")
for k in (2, 5, 7, 9):
    h = open(f"{ref}/TRIKE-{k}/src/trike_params.h").read()
    g = lambda n: int(re.search(rf"#define {n}\s+(\d+)", h).group(1))
    r, d, s, ss = g("PARAM_R"), g("PARAM_D"), g("PARAM_S"), g("PARAM_SS")
    rng = random.Random(k); N = 200; lit = bino = 0
    for _ in range(N):
        H = [rng.sample(range(r), d) for _ in range(3)]
        def intra(a):
            m = {}
            for i in range(d):
                for j in range(i):
                    y = (a[j] - a[i]) % r; y = min(y, r - y); m[y] = m.get(y, 0) + 1
            return m.values()
        def inter(a, b):
            m = {}
            for x in a:
                for y in b:
                    z = (y - x) % r; m[z] = m.get(z, 0) + 1
            return m.values()
        I = [list(intra(a)) for a in H]; X = [list(inter(H[i], H[(i + 1) % 3])) for i in range(3)]
        lit += any(sum(v * v for v in t) > s for t in I) or any(sum(v * v for v in t) > ss for t in X)
        bino += any(sum(comb(v, 2) for v in t) > s for t in I) or any(sum(comb(v, 2) for v in t) > ss for t in X)
    print(f"TRIKE-{k:<2} {d:4d} {comb(d,2):7d} {s:5d} {d*d:6d} {ss:5d} | {lit:4d}/{N} ({100*lit/N:5.1f}%)          | {bino}/{N}")
