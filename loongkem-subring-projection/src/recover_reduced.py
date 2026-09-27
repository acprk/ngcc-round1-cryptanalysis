#!/usr/bin/env python
"""Reduced-scale EXACT recovery validating the LoongKEM sub-ring projection pipeline.

Run:  sage -python recover_reduced.py <dim>          (<dim> in {40,55})

We build a SCALED-DOWN module-LWE instance with the SAME structure as the real
attack and recover the planted projected secret EXACTLY by primal (Kannan)
embedding + BKZ.  The secret is self-planted, so exact recovery is verified by
direct comparison (legitimate self-scoring for a toy instance).

Structure mirrored from the real attack (paper sec:tech):
  * ring blocks live in R_N = Z_q[X]/(X^N+1) with N non-power-of-two, N/d odd,
    so X^d+1 | X^N+1 and psi: R_N -> R_d is a ring hom (block-anti-circulant
    structure: multiplication by a ring element = negacyclic d x d block);
  * we project A, s, e via psi;  psi scales noise variance by exactly N/d
    (sqrt(N/d) on sigma), the paper's scaling;
  * the projected instance is a genuine MLWE over R_d that we expand to a scalar
    LWE (A_scalar : M x n, b = A_scalar s + e mod q) and solve by lattice reduction.

Config:
  dim 40 -> d=4, N=12 (N/d=3), k=10 secret blocks  -> n=40, BKZ block size 20
  dim 55 -> d=5, N=15 (N/d=3), k=11 secret blocks  -> n=55, BKZ block size 30
"""
import sys, time
from fpylll import IntegerMatrix, LLL, BKZ, GSO


Q = 8191
ETA = 3   # CBD parameter for the toy secret/error (small, like the real sets)


def cbd(rng, eta):
    """One centered-binomial sample of parameter eta."""
    return sum(rng.randint(0, 1) for _ in range(eta)) - sum(rng.randint(0, 1) for _ in range(eta))


def psi(f, N, d):
    """Ring hom R_N -> R_d :  X^j |-> (-1)^floor(j/d) X^(j mod d)."""
    out = [0] * d
    for i, fi in enumerate(f):
        out[i % d] += (-fi if ((i // d) % 2) else fi)
    return out


def negmul(a, b, d, q):
    """Negacyclic product in R_d = Z_q[X]/(X^d+1)."""
    t = [0] * (2 * d)
    for i in range(d):
        for j in range(d):
            t[i + j] += a[i] * b[j]
    return [(t[i] - t[i + d]) % q for i in range(d)]


def negmat(a, d, q):
    """d x d matrix of multiplication-by-a in R_d (anti-circulant / negacyclic)."""
    M = [[0] * d for _ in range(d)]
    for j in range(d):
        ej = [0] * d
        ej[j] = 1
        col = negmul(a, ej, d, q)
        for i in range(d):
            M[i][j] = col[i]
    return M


def build_instance(d, N, k_blocks, m_blocks, eta, q, seed):
    """Return (A_scalar M x n, b [M], s_true [n], sigma_e_empirical)."""
    import random
    rng = random.Random(seed)
    scale = N // d
    n = k_blocks * d
    M = m_blocks * d

    # planted secret: k blocks, each a small poly in R_N projected to R_d
    s_proj = []          # list of k blocks (each length d)
    for _ in range(k_blocks):
        sN = [cbd(rng, eta) for _ in range(N)]
        s_proj.append(psi(sN, N, d))
    s_true = [c for blk in s_proj for c in blk]     # length n

    # A: m_blocks x k_blocks ring elements, each = psi(random anti-circulant gen in R_N)
    A_scalar = [[0] * n for _ in range(M)]
    for bi in range(m_blocks):
        for bj in range(k_blocks):
            aN = [rng.randrange(q) for _ in range(N)]     # uniform ring element in R_N
            ad = psi(aN, N, d)                            # projected -> R_d
            blk = negmat(ad, d, q)                        # d x d negacyclic block
            for r in range(d):
                for c in range(d):
                    A_scalar[bi * d + r][bj * d + c] = blk[r][c]

    # b = A s + e  (mod q), e = psi(small e_N), variance scaled by N/d
    errs = []
    b = [0] * M
    for bi in range(m_blocks):
        eN = [cbd(rng, eta) for _ in range(N)]
        ed = psi(eN, N, d)
        errs.extend(ed)
        for r in range(d):
            acc = sum(A_scalar[bi * d + r][c] * s_true[c] for c in range(n))
            b[bi * d + r] = (acc + ed[r]) % q

    var_e = sum(x * x for x in errs) / len(errs)
    return A_scalar, b, s_true, var_e ** 0.5, scale


def primal_recover(A_scalar, b, q, beta):
    """Primal Kannan embedding + BKZ. Returns recovered secret list or None."""
    M = len(A_scalar)
    n = len(A_scalar[0])
    D = M + n + 1
    # basis rows:
    #  [ q I_M | 0    | 0 ]
    #  [ A     | I_n  | 0 ]   (A is M x n, rows indexed by secret coord? -> use A^T)
    #  [ b     | 0    | 1 ]
    # combination (k, x, w=-1) gives first M coords = q k + A x - b ; middle = x ; last = -1
    B = IntegerMatrix(D, D)
    for i in range(M):
        B[i, i] = q
    for j in range(n):                       # secret-coord rows
        row = M + j
        for i in range(M):
            B[row, i] = A_scalar[i][j]
        B[row, M + j] = 1
    for i in range(M):
        B[D - 1, i] = b[i]
    B[D - 1, D - 1] = 1

    LLL.reduction(B)
    par = BKZ.Param(block_size=beta, strategies=BKZ.DEFAULT_STRATEGY,
                    flags=BKZ.AUTO_ABORT | BKZ.GH_BND)
    BKZ.reduction(B, par)

    # scan rows for the embedding vector with last coord = +-1 -> extract s
    for r in range(D):
        last = B[r, D - 1]
        if last in (1, -1):
            sgn = -last          # w = -last... we used w=-1 giving last=-1 => middle = x = s
            cand = [sgn * B[r, M + j] for j in range(n)]
            return cand
    return None


def main():
    dim = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    if dim == 40:
        d, N, k, m_blocks, beta = 4, 12, 10, 14, 20
    elif dim == 55:
        d, N, k, m_blocks, beta = 5, 15, 11, 15, 30
    else:
        print("unsupported dim", dim); sys.exit(1)

    n = k * d
    M = m_blocks * d
    print("Reduced-scale LoongKEM sub-ring projection recovery")
    print("  projection R_%d -> R_%d  (N/d=%d, sqrt(N/d)=%.4f noise scaling)"
          % (N, d, N // d, (N // d) ** 0.5))
    print("  secret dim n = k*d = %d   scalar samples M = m_blocks*d = %d   q = %d"
          % (n, M, Q))
    print("  BKZ block size beta = %d   embedding lattice dim = %d" % (beta, M + n + 1))

    A, b, s_true, sigma_e, scale = build_instance(d, N, k, m_blocks, ETA, Q, seed=12345)
    print("  planted secret sigma_s(empirical)=%.3f  projected error sigma_e(empirical)=%.3f"
          % ((sum(x * x for x in s_true) / n) ** 0.5, sigma_e))

    t0 = time.time()
    rec = primal_recover(A, b, Q, beta)
    dt = time.time() - t0

    # compare (allow global sign flip: the embedding may return -s)
    def eq(a, c):
        return all((x - y) % Q == 0 for x, y in zip(a, c))
    ok = rec is not None and (eq(s_true, rec) or eq(s_true, [-x for x in rec]))
    print("  BKZ wall-clock: %.3f s" % dt)
    if ok:
        print("  RESULT: EXACT RECOVERY OK  (recovered projected secret == planted secret)")
    else:
        print("  RESULT: recovery FAILED")
        if rec is not None:
            mism = sum(1 for x, y in zip(s_true, rec) if (x - y) % Q and (x + y) % Q)
            print("    mismatches: %d / %d   recovered head=%s planted head=%s"
                  % (mism, n, rec[:8], s_true[:8]))
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
