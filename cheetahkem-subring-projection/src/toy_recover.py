# Scaled end-to-end validation of the sub-ring-projection recovery pipeline.
# Same (q, secret/error distributions) as the real projected Cheetah128 instance,
# smaller dimension n0 so plain fpylll BKZ2.0 (no sieving) can finish -> proves the
# projection+primal-embedding+BKZ recovery works, and calibrates the estimator.
from fpylll import IntegerMatrix, LLL, BKZ, GSO
from fpylll.algorithms.bkz2 import BKZReduction
import time, sys
sage_seed = 12345
import random; random.seed(sage_seed)
q = 7681
SIG_S, SIG_E = 3.54, 6.38   # measured projected Cheetah128 secret/error sigmas

def dgauss(sig):
    # simple discrete gaussian via rounded normal
    import random, math
    return int(round(random.gauss(0, sig)))

def build_and_solve(n0, betas):
    m = n0                      # K=1: one ring element -> n samples (m=n), as in the real attack
    A = [[random.randrange(q) for _ in range(n0)] for _ in range(m)]
    s = [dgauss(SIG_S) for _ in range(n0)]
    e = [dgauss(SIG_E) for _ in range(m)]
    b = [(sum(A[i][j]*s[j] for j in range(n0)) + e[i]) % q for i in range(m)]
    # primal (Kannan) embedding, dim d = m+n0+1
    d = m + n0 + 1
    M = IntegerMatrix(d, d)
    for i in range(m):
        M[i,i] = q
    for i in range(n0):
        for j in range(m):
            M[m+i, j] = A[j][i]
        M[m+i, m+i] = 1
    for j in range(m):
        M[d-1, j] = b[j]
    M[d-1, d-1] = 1
    t0=time.time(); LLL.reduction(M); tll=time.time()-t0
    ok=False; used=None
    for beta in betas:
        t0=time.time()
        par = BKZ.Param(block_size=beta, strategies=BKZ.DEFAULT_STRATEGY, max_loops=8)
        BKZReduction(M)(par)
        dt=time.time()-t0
        # check shortest rows for the embedded (e | s | -1) vector
        for r in range(min(4,d)):
            row=[M[r,k] for k in range(d)]
            if abs(row[d-1])==1:
                sign=-row[d-1]
                cand_e=[sign*row[k] for k in range(m)]
                cand_s=[sign*row[m+k] for k in range(n0)]
                if cand_s==s or [ -x for x in cand_s]==s or cand_e==e:
                    ok=True; used=beta
                    print(f"n0={n0}: RECOVERED at beta={beta} (LLL {tll:.1f}s, BKZ {dt:.1f}s)")
                    break
        if ok: break
        print(f"n0={n0}: beta={beta} no ({dt:.1f}s)")
    if not ok: print(f"n0={n0}: NOT recovered up to beta={betas[-1]}")
    return ok, used

for n0 in [40, 56, 72]:
    build_and_solve(n0, [20,30,40,50,60])
    sys.stdout.flush()
