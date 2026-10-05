"""Both BAG-Loong instances at all four parameter sets, three values of omega.

key instance  : S_j = [H | I](X_j ; Y_j)        -> [2n, n]_{q^m},      r = A_XY union
ct  instance  : (R1 | E|R2) with eq. (2)        -> [2n+n1, n]_{q^m},   r = A_R  union
"""
from cryptographic_estimators.RankSDEstimator import RankSDEstimator

SETS = {  # name: (m, n, n1, A_XY=(t1,g,t2), A_R=(t1,g,t2))
    "128": (47, 42, 10, (5, 4, 5), (5, 3, 5)),
    "256": (67, 65, 12, (5, 3, 6), (6, 3, 6)),
    "384": (83, 83, 14, (6, 3, 6), (7, 4, 7)),
    "512": (97, 104, 15, (7, 4, 7), (7, 4, 7)),
}

inst = {}
for name, (m, n, n1, axy, ar) in SETS.items():
    inst[f"{name}-key"] = (2, m, 2 * n, n, axy[0] + axy[2] - axy[1])
    inst[f"{name}-ct"] = (2, m, 2 * n + n1, n, ar[0] + ar[2] - ar[1])
# control: the 128 key instance priced as two independent blocks (what Table 5 does)
inst["128-key-nomerge"] = (2, 47, 84, 42, 10)

for w in (2, 2.81, 3):
    for name, (q, m, N, k, r) in inst.items():
        res = RankSDEstimator(q, m, N, k, r, bit_complexities=1, w=w).estimate()
        d = {
            a: round(v["estimate"]["time"], 1)
            for a, v in res.items()
            if isinstance(v["estimate"]["time"], (int, float))
        }
        b = min(d, key=d.get)
        print(f"w={w} {name} (q,m,N,k,r)={(q, m, N, k, r)} best={b} {d[b]} all={d}",
              flush=True)
