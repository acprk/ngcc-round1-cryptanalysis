#!/usr/bin/env python3
"""BAG-Loong key recovery: the blended error (X_j | Y_j) is a rank-(t1+t2-g) error,
so one super-support guess suffices.  Two attackers are run against the same
instances and the same linear-algebra step:

  merged : guess ONE subspace F of dimension r', hope F contains VX + VY
           Pr ~ q^{-(t1+t2-g)(m-r')}          <- what a generic rank decoder pays
  block  : guess F1 of dim r' containing VX and F2 of dim r' containing VY,
           independently.  Pr ~ q^{-t1(m-r')-t2(m-r')}
           <- what spec Sec. 3.3.2 / Table 5 prices (its asymptotic success
              probability 2^{-t1(m-r1)-t2(m-r2)+m} charges t1+t2 dimensions)

Both attackers solve the identical F_2 system (same unknown count 2*n*r'), so the
measured ratio of iteration counts isolates the mis-pricing: it should be
q^{g(m-r')}.

The instance is built exactly as BAG-Loong.KeyGen does (spec Algorithm 1):
H uniform in F_{q^m}^{n x n}, X on support VX, Y on support VY with
dim(VX n VY) = g and 1 in VY, S = H X + Y.

Usage: merged_vs_block.py m n t1 t2 g rprime n1 trials seed [iter_cap]
"""
import math
import random
import sys

# primitive / irreducible polynomials x^m + ... + 1, as bit masks
POLY = {
    7: 0b10000011,
    8: 0b100011011,
    9: 0b1000010001,
    10: 0b10000001001,
    11: 0b100000000101,
    12: 0b1000001010011,
    13: 0b10000000011011,
}


def make_field(m):
    poly = POLY[m]

    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            b >>= 1
            a <<= 1
            if a >> m:
                a ^= poly
        return r

    return mul


def rank_of(vs):
    piv = {}
    r = 0
    for v in vs:
        for b in sorted(piv, reverse=True):
            if v >> b & 1:
                v ^= piv[b]
        if v:
            piv[v.bit_length() - 1] = v
            r += 1
    return r


def rand_subspace(m, dim, rng, contain=()):
    basis = list(contain)
    while len(basis) < dim:
        v = rng.getrandbits(m)
        if v and rank_of(basis + [v]) == len(basis) + 1:
            basis.append(v)
    return basis


def span_elt(basis, rng):
    v = 0
    for b in basis:
        if rng.getrandbits(1):
            v ^= b
    return v


def solve_gf2(rows, ncols):
    """rows: list of (lhs_bitmask, rhs_bit).  Returns one solution bitmask or None."""
    piv = []  # (col, row)
    mat = list(rows)
    r = 0
    for c in range(ncols):
        sel = None
        for i in range(r, len(mat)):
            if mat[i][0] >> c & 1:
                sel = i
                break
        if sel is None:
            continue
        mat[r], mat[sel] = mat[sel], mat[r]
        lhs, rhs = mat[r]
        for i in range(len(mat)):
            if i != r and (mat[i][0] >> c & 1):
                mat[i] = (mat[i][0] ^ lhs, mat[i][1] ^ rhs)
        piv.append((c, r))
        r += 1
        if r == len(mat):
            break
    for i in range(r, len(mat)):
        if mat[i][0] == 0 and mat[i][1]:
            return None  # inconsistent
    sol = 0
    for c, i in piv:
        if mat[i][1]:
            sol |= 1 << c
    return sol


class Instance:
    """One BAG-Loong-shaped key: S = H X + Y over F_{q^m}, X,Y in F^{n x n1}."""

    def __init__(self, m, n, t1, t2, g, n1, rng):
        self.m, self.n, self.n1 = m, n, n1
        self.t1, self.t2, self.g = t1, t2, g
        self.mul = make_field(m)
        # blended supports: g shared dimensions, 1 in VY (spec KeyGen)
        shared = rand_subspace(m, g, rng, contain=[1])
        self.VX = rand_subspace(m, t1, rng, contain=shared)
        self.VY = rand_subspace(m, t2, rng, contain=shared)
        assert rank_of(self.VX) == t1 and rank_of(self.VY) == t2
        assert rank_of(self.VX + self.VY) == t1 + t2 - g
        self.U = self.VX + self.VY
        self.H = [[rng.getrandbits(m) for _ in range(n)] for _ in range(n)]
        self.X = [[span_elt(self.VX, rng) for _ in range(n1)] for _ in range(n)]
        self.Y = [[span_elt(self.VY, rng) for _ in range(n1)] for _ in range(n)]
        self.S = [[0] * n1 for _ in range(n)]
        for i in range(n):
            for j in range(n1):
                acc = self.Y[i][j]
                for k in range(n):
                    acc ^= self.mul(self.H[i][k], self.X[k][j])
                self.S[i][j] = acc

    def contains(self, F):
        """does span(F) contain the support it must, for each attacker?"""
        return rank_of(F) == rank_of(F + self.U)

    def solve_with(self, FX, FY, col):
        """Solve column `col` assuming Supp(X) <= span(FX), Supp(Y) <= span(FY).
        Returns (x, y) lists or None."""
        n, m, mul = self.n, self.m, self.mul
        rx, ry = len(FX), len(FY)
        ncols = n * rx + n * ry
        rows = []
        for i in range(n):
            # sum_k H[i][k] x_k + y_i = S[i][col], as m F_2 equations
            colbits = [0] * m
            for k in range(n):
                for a in range(rx):
                    prod = mul(self.H[i][k], FX[a])
                    cidx = k * rx + a
                    for bit in range(m):
                        if prod >> bit & 1:
                            colbits[bit] |= 1 << cidx
            for a in range(ry):
                cidx = n * rx + i * ry + a
                for bit in range(m):
                    if FY[a] >> bit & 1:
                        colbits[bit] |= 1 << cidx
            for bit in range(m):
                rows.append((colbits[bit], (self.S[i][col] >> bit) & 1))
        sol = solve_gf2(rows, ncols)
        if sol is None:
            return None
        x = []
        y = []
        for k in range(n):
            v = 0
            for a in range(rx):
                if sol >> (k * rx + a) & 1:
                    v ^= FX[a]
            x.append(v)
        for i in range(n):
            v = 0
            for a in range(ry):
                if sol >> (n * rx + i * ry + a) & 1:
                    v ^= FY[a]
            y.append(v)
        return x, y


def attack(inst, mode, rprime, rng, cap):
    """Return (iterations, recovered_all_columns) or (cap, False)."""
    m = inst.m
    r = inst.t1 + inst.t2 - inst.g
    for it in range(1, cap + 1):
        if mode == "merged":
            F = rand_subspace(m, rprime, rng)
            FX = FY = F
            hit = rank_of(F) == rank_of(F + inst.U)
        else:  # per-block guesses, independent
            F1 = rand_subspace(m, rprime, rng)
            F2 = rand_subspace(m, rprime, rng)
            FX, FY = F1, F2
            hit = (rank_of(F1) == rank_of(F1 + inst.VX)) and (
                rank_of(F2) == rank_of(F2 + inst.VY)
            )
        if not hit:
            continue
        got = inst.solve_with(FX, FY, 0)
        if got is None:
            continue
        x, y = got
        if rank_of(x + y) > r:
            continue
        if x != [row[0] for row in inst.X]:
            continue
        # the support is now known: every remaining column is one linear solve
        allcols = True
        for j in range(1, inst.n1):
            g2 = inst.solve_with(FX, FY, j)
            if g2 is None or g2[0] != [row[j] for row in inst.X]:
                allcols = False
                break
        return it, allcols
    return cap, False


def gbin(a, b):
    num = den = 1
    for i in range(b):
        num *= 2 ** (a - i) - 1
        den *= 2 ** (b - i) - 1
    return num / den


def prob_mode():
    """Empirical hit rates vs the exact Gaussian-binomial predictions.

    The per-block attacker's two guesses are independent by construction, so its
    hit rate factorises as Pr[F1 >= VX] * Pr[F2 >= VY].  Each factor is measured
    separately, which is why a shape whose joint probability is far below the
    sample budget can still be checked tightly.
    """
    m, t1, t2, g, rp, samples, seed = (int(v) for v in sys.argv[2:9])
    rng = random.Random(seed)
    r = t1 + t2 - g
    shared = rand_subspace(m, g, rng, contain=[1])
    VX = rand_subspace(m, t1, rng, contain=shared)
    VY = rand_subspace(m, t2, rng, contain=shared)
    U = VX + VY
    assert rank_of(U) == r
    hits = {"merged": 0, "x": 0, "y": 0}
    targets = (("merged", U), ("x", VX), ("y", VY))
    for _ in range(samples):
        for key, space in targets:
            F = rand_subspace(m, rp, rng)
            if rank_of(F + space) == rp:
                hits[key] += 1

    def rate(k):
        return hits[k] / samples

    pm = gbin(m - r, rp - r) / gbin(m, rp)
    px = gbin(m - t1, rp - t1) / gbin(m, rp)
    py = gbin(m - t2, rp - t2) / gbin(m, rp)
    meas_block = rate("x") * rate("y")
    print(f"m={m} A=[[{t1},{g}],[{g},{t2}]] r={r} r'={rp} samples={samples} each")
    for k, pred in (("merged", pm), ("x", px), ("y", py)):
        obs = rate(k)
        lo = math.log2(obs) if obs else float("-inf")
        print(
            f"  Pr[F contains {k:6s}] hits={hits[k]:7d} measured 2^{lo:8.3f} "
            f"predicted 2^{math.log2(pred):8.3f}"
        )
    print(
        f"  per-block joint = product of the two measured factors: "
        f"2^{math.log2(meas_block) if meas_block else float('-inf'):.3f} "
        f"(predicted 2^{math.log2(px * py):.3f})"
    )
    if meas_block and rate("merged"):
        print(
            f"RESULT advantage of merging: measured "
            f"2^{math.log2(rate('merged') / meas_block):.3f}  "
            f"predicted 2^{math.log2(pm / (px * py)):.3f}"
        )


def main():
    if sys.argv[1] == "prob":
        return prob_mode()
    m, n, t1, t2, g, rp, n1, trials, seed = (int(v) for v in sys.argv[1:10])
    cap = int(sys.argv[10]) if len(sys.argv) > 10 else 1 << 22
    modes = sys.argv[11].split(",") if len(sys.argv) > 11 else ["merged", "block"]
    rng = random.Random(seed)
    r = t1 + t2 - g
    assert 2 * n * rp <= n * m, "need 2*n*r' <= n*m equations"

    p_merged = gbin(m - r, rp - r) / gbin(m, rp)
    p_x = gbin(m - t1, rp - t1) / gbin(m, rp)
    p_y = gbin(m - t2, rp - t2) / gbin(m, rp)
    p_block = p_x * p_y

    print(
        f"m={m} n={n} n1={n1} A=[[{t1},{g}],[{g},{t2}]] merged rank r={r} "
        f"(blocks separate t1+t2={t1 + t2})  guess dim r'={rp}"
    )
    print(
        f"predicted iterations: merged 2^{math.log2(1 / p_merged):.2f}   "
        f"per-block 2^{math.log2(1 / p_block):.2f}   "
        f"ratio 2^{math.log2(p_merged / p_block):.2f}"
    )
    out = {}
    for mode in modes:
        its = []
        full = 0
        for t in range(trials):
            inst = Instance(m, n, t1, t2, g, n1, rng)
            it, allcols = attack(inst, mode, rp, rng, cap)
            its.append(it)
            full += allcols
            print(
                f"  {mode:6s} trial {t}: iterations={it} all_{n1}_columns={allcols}",
                flush=True,
            )
        mean = sum(its) / len(its)
        out[mode] = mean
        print(
            f"RESULT {mode}: trials={trials} full_key_recoveries={full}/{trials} "
            f"mean_iterations={mean:.1f} (2^{math.log2(mean):.2f})"
        )
    print(
        "NOTE: per-block means are censored by the iteration cap "
        f"({cap}); use the `prob` mode for the ratio."
    )


if __name__ == "__main__":
    main()
