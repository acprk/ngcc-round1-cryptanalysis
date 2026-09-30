#!/usr/bin/env sage -python
"""
Independent lattice-estimator re-estimate of Scloud+ (NGCC KEM), all five levels.

Usage:
  nice -n 10 sage -python scloud_est.py LEVEL INSTANCE DISTMODEL [ATTACKS] [COSTMODELS]
    LEVEL      128|192|256|384|512
    INSTANCE   key  (secret S: dim n, m samples)
               ct   (secret S': dim m, n + nbar samples; (A|B) treated as uniform)
    DISTMODEL  fw   fixed-weight SparseTernary at the expected weight  (estimator-native)
               iid  exact i.i.d. BD_rho ternary (custom ND class below, exact variance,
                    exact "most-likely-first" guessing support size)
    ATTACKS    comma list (default: all)
    COSTMODELS comma list of MATZOV,MATZOVq,CoreSVP,CoreSVPq (default: all)
Output: one JSON line per (attack, cost model) on stdout.

Estimator: /home/luck/xzy/lattice-estimator commit 5ba00f5 (same commit as FrodoKEM ePrint 2025/1861).
"""
import sys, json, time, signal
import os
sys.path.insert(0, os.environ.get('ESTIMATOR', os.path.expanduser('~/lattice-estimator')))
from estimator import LWE, ND, RC
from estimator.nd import NoiseDistribution, SparseTernary
from estimator.reduction import ADPS16, MATZOV as MATZOV_RC
from estimator import lwe_dual
from sage.all import RealField, binomial, sqrt, ceil, log, oo, QQ

R = RealField(200)

# ---------------------------------------------------------------------------
# Parameters (Reference_Implementation/Scloudplus-*/kem/parameters.h; spec Table 2)
# BD_p: coefficient = Ber(1/p) - Ber(1/p)  (spec Def. 1, Alg. 1; common/sample.c)
PARAMS = {
    128: dict(m=608,  n=608,  mbar=8,  nbar=8,  ps=4,  pe=2),
    192: dict(m=832,  n=832,  mbar=12, nbar=11, ps=2,  pe=2),
    256: dict(m=1184, n=1184, mbar=12, nbar=11, ps=6,  pe=6),
    384: dict(m=1664, n=1664, mbar=16, nbar=16, ps=6,  pe=6),
    512: dict(m=2400, n=2400, mbar=16, nbar=16, ps=12, pe=12),
}
Q = 1024


class IIDTernary(NoiseDistribution):
    """i.i.d. coefficients with P(+1)=P(-1)=r(1-r), P(0)=1-2r(1-r), r=1/p (BD_p).

    * stddev exact (sqrt(2 r (1-r))), bounds (-1,1).
    * is_sparse=False so that the dual-hybrid code takes the i.i.d. branch (the sparse branch
      raises NotImplementedError for non-SparseTernary); sparsity is instead exploited exactly
      through support_size(fraction): the attacker enumerates vectors in decreasing probability
      order (= increasing Hamming weight since P(+-1) < P(0)), and we return the smallest such
      set carrying probability mass >= fraction.
    * hamming_weight = round(n * density) (used by primal_hybrid's prob_drop, i.e. the same
      approximation the fixed-weight model makes there).
    """
    def __init__(self, p, n=None):
        self.p_bd = int(p)
        r = QQ(1) / self.p_bd
        self.p1 = r * (1 - r)          # P(+1) = P(-1)
        dens = 2 * self.p1
        if n is None:
            n = 0
        super().__init__(n=n, mean=0, stddev=sqrt(R(dens)), bounds=(-1, 1), _density=R(dens))

    def __hash__(self):
        return hash(("IIDTernary", self.p_bd, self.n))

    def __eq__(self, other):
        return isinstance(other, IIDTernary) and (self.p_bd, self.n) == (other.p_bd, other.n)

    def resize(self, new_n):
        return IIDTernary(self.p_bd, new_n)

    @property
    def is_sparse(self):
        return False

    def support_size(self, fraction=1.0):
        n = int(self.n)
        if n == 0:
            return 1
        fraction = R(fraction)
        p1 = R(self.p1)
        p0 = 1 - 2 * p1
        cum_p, cum_sz = R(0), R(0)
        for w in range(n + 1):
            cnt = R(binomial(n, w)) * R(2) ** w
            pv = p1 ** w * p0 ** (n - w)           # probability of one vector of weight w
            pw = cnt * pv
            if cum_p + pw >= fraction:
                need = (fraction - cum_p) / pv
                return ceil(cum_sz + need)
            cum_p += pw
            cum_sz += cnt
        return ceil(cum_sz)

    def __repr__(self):
        return f"BD(1/{self.p_bd}, n={self.n})"

    __str__ = __repr__


def fw(p, n):
    """fixed-weight SparseTernary with the expected number of +1 / -1 of BD_p over n coords."""
    r = QQ(1) / p
    k = int(round(n * r * (1 - r)))
    return SparseTernary(k, k, n)


def instance(level, inst, dm):
    P = PARAMS[level]
    if inst == "key":
        n_s, m_s = P["n"], P["m"]
    elif inst == "ct":
        n_s, m_s = P["m"], P["n"] + P["nbar"]
    else:
        raise ValueError(inst)
    if dm == "fw":
        Xs, Xe = fw(P["ps"], n_s), fw(P["pe"], m_s)
    elif dm == "iid":
        Xs, Xe = IIDTernary(P["ps"], n_s), IIDTernary(P["pe"], m_s)
    else:
        raise ValueError(dm)
    return LWE.Parameters(n=n_s, q=Q, Xs=Xs, Xe=Xe, m=m_s, tag=f"Scloud+{level}-{inst}-{dm}")


COST_MODELS = {
    "MATZOV":   MATZOV_RC(),                 # list_decoding-classical  (estimator default)
    "MATZOVq":  MATZOV_RC(nn="quantum"),     # list_decoding-dw (depth x width)
    "CoreSVP":  ADPS16("classical"),         # 2^(0.292 beta)
    "CoreSVPq": ADPS16("quantum"),           # 2^(0.265 beta)
}

ATTACKS = {
    "usvp":             lambda P, cm: LWE.primal_usvp(P, red_cost_model=cm),
    "bdd":              lambda P, cm: LWE.primal_bdd(P, red_cost_model=cm),
    "bdd_hybrid":       lambda P, cm: LWE.primal_hybrid(P, mitm=False, babai=False, red_cost_model=cm),
    "bdd_mitm_hybrid":  lambda P, cm: LWE.primal_hybrid(P, mitm=True, babai=True, red_cost_model=cm),
    "dual":             lambda P, cm: LWE.dual(P, red_cost_model=cm),
    # LWE.dual_hybrid in this estimator version == MATZOV22 dual-sieve-FFT hybrid
    "dual_hybrid":      lambda P, cm: LWE.dual_hybrid(P, red_cost_model=cm),
    # classical [EspJouKha20] dual hybrid (sparse-aware), and its MitM variant
    "dual_hybrid_EJK":  lambda P, cm: lwe_dual.dual_hybrid(P, red_cost_model=cm),
    "dual_mitm_hybrid": lambda P, cm: lwe_dual.dual_hybrid(P, red_cost_model=cm, mitm_optimization=True),
    "arora-gb":         lambda P, cm: LWE.arora_gb(P),
}


class Timeout(Exception):
    pass


def _alarm(sig, frm):
    raise Timeout()


def lg(x):
    try:
        return float(log(x, 2))
    except Exception:
        return None


def main():
    level, inst, dm = int(sys.argv[1]), sys.argv[2], sys.argv[3]
    attacks = sys.argv[4].split(",") if len(sys.argv) > 4 and sys.argv[4] != "all" else list(ATTACKS)
    cms = sys.argv[5].split(",") if len(sys.argv) > 5 else list(COST_MODELS)
    tmo = int(sys.argv[6]) if len(sys.argv) > 6 else 5400
    P = instance(level, inst, dm)
    signal.signal(signal.SIGALRM, _alarm)
    for a in attacks:
        for cmn in cms:
            if a == "arora-gb" and cmn != cms[0]:
                continue
            rec = dict(level=level, inst=inst, dm=dm, attack=a, cm=cmn, params=repr(P))
            t0 = time.time()
            signal.alarm(tmo)
            try:
                r = ATTACKS[a](P, COST_MODELS[cmn])
                signal.alarm(0)
                rec["log2rop"] = lg(r["rop"])
                for k in ("beta", "eta", "zeta", "d", "m", "t", "p", "h1", "k", "prob", "|S|", "red", "guess", "svp", "repetitions"):
                    if k in r:
                        v = r[k]
                        rec[k] = lg(v) if k in ("red", "guess", "svp", "|S|") else (float(v) if v not in (oo,) else "oo")
            except Timeout:
                rec["error"] = f"TIMEOUT {tmo}s"
            except Exception as e:
                signal.alarm(0)
                rec["error"] = repr(e)[:200]
            rec["secs"] = round(time.time() - t0, 1)
            print(json.dumps(rec, default=str), flush=True)


if __name__ == "__main__":
    main()
