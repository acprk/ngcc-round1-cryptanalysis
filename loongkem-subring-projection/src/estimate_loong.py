#!/usr/bin/env python
"""Lattice-estimator cost of the SUB-RING PROJECTED LoongKEM instances.

Run:  PYTHONPATH=<lattice-estimator> sage -python estimate_loong.py
(the wrapper run_all.sh / the __main__ block below insert the path for you).

For each non-power-of-two set we project R_q=Z_q[X]/(X^N+1) onto R_d=Z_q[X]/(X^d+1)
with d|N and N/d odd, via psi (see paper eq. (2)).  psi is a ring hom; each output
coefficient is a signed sum of N/d inputs, so BOTH secret and error variances grow
by exactly N/d.  The projected MLWE instance is:

    psi(b1) = psi(A1) psi(s1) + psi(A2) psi(s2) + psi(e1)

    secret dimension   n = (K1+K2)*d
    #scalar samples    m = K1*d
    modulus            q = 8191
    error   variance   var_e1 * (N/d)     with var_e1 = eta/2 + step^2/12
    secret  variance   (eta/2) * (N/d)

where step = 2^(QBITS-DB) is the ciphertext-compression rounding step applied to b1
by the reference implementation (decompress(., QBITS-DB) in KEM_Loong.c), which adds
a uniform rounding term of variance step^2/12 to the transmitted-row noise.

We report primal-uSVP (headline), and BDD + dual as cross-checks.
All costs are the estimator's classical "rop" (bit-operations, log2).
"""
import sys, os

# --- make the lattice-estimator importable under sage -----------------------
EST = os.environ.get("LATTICE_ESTIMATOR", os.path.expanduser("~/xzy/lattice-estimator"))
if EST not in sys.path:
    sys.path.insert(0, EST)
from estimator import *          # noqa: E402,F401,F403
from sage.all import sqrt, log, RR  # noqa: E402


# reference params.h values (src/LoongKEM, read-only), matching paper Table 1
SETS = [
    # name        N   K1  K2  eta  d   DB  QBITS  claimed
    ("Loong128",  12, 48, 4,  5,   4,  10, 13,    128),
    ("Loong384",  20, 72, 8,  3,   4,  11, 13,    384),
    ("Loong512",  24, 80, 10, 2,   8,  11, 13,    512),
]
Q = 8191


def projected_params(N, K1, K2, eta, d, DB, QBITS):
    """Return (n, m, sigma_e, sigma_s) of the projected MLWE instance."""
    scale = N // d                      # variance blow-up factor N/d
    step = 2 ** (QBITS - DB)            # compression rounding step on b1
    var_e1 = eta / 2.0 + step * step / 12.0
    var_s1 = eta / 2.0
    sigma_e = sqrt(RR(var_e1 * scale))
    sigma_s = sqrt(RR(var_s1 * scale))
    n = (K1 + K2) * d
    m = K1 * d
    return n, m, sigma_e, sigma_s


def run_set(name, N, K1, K2, eta, d, DB, QBITS, claimed):
    n, m, sigma_e, sigma_s = projected_params(N, K1, K2, eta, d, DB, QBITS)
    print("=" * 74)
    print("%s : project R_%d -> R_%d   (N/d = %d, compression step 2^%d)"
          % (name, N, d, N // d, QBITS - DB))
    print("  projected secret dim n = (K1+K2)*d = %d" % n)
    print("  #scalar samples    m = K1*d       = %d   (n-m = %d = K2*d, the s2 guess)"
          % (m, n - m))
    print("  q = %d   sigma_e = %.4f   sigma_s = %.4f" % (Q, sigma_e, sigma_s))
    print("-" * 74)

    params = LWE.Parameters(
        n=n, q=Q,
        Xs=ND.DiscreteGaussian(RR(sigma_s)),
        Xe=ND.DiscreteGaussian(RR(sigma_e)),
        m=m,
        tag=name,
    )
    print("Estimator parameter object:")
    print("  ", params)
    print("-" * 74)

    results = {}
    # headline: primal uSVP (Kannan embedding + BKZ)
    try:
        r = LWE.primal_usvp(params, red_shape_model="gsa")
        results["primal_usvp"] = r
        print("primal_usvp : rop=2^%.1f  beta=%s  d=%s"
              % (float(log(r["rop"], 2)), r.get("beta"), r.get("d")))
    except Exception as ex:
        print("primal_usvp : FAILED:", ex)

    # cross-check: primal BDD (decoding)
    try:
        r = LWE.primal_bdd(params)
        results["primal_bdd"] = r
        print("primal_bdd  : rop=2^%.1f  beta=%s  eta=%s"
              % (float(log(r["rop"], 2)), r.get("beta"), r.get("eta")))
    except Exception as ex:
        print("primal_bdd  : FAILED:", ex)

    # cross-check: dual / dual-hybrid
    try:
        r = LWE.dual(params)
        results["dual"] = r
        print("dual        : rop=2^%.1f  beta=%s"
              % (float(log(r["rop"], 2)), r.get("beta")))
    except Exception as ex:
        print("dual        : FAILED:", ex)

    print("claimed security: %d bits" % claimed)
    hl = results.get("primal_usvp")
    if hl is not None:
        print(">>> %s projected primal-uSVP cost = 2^%.1f  (claimed %d)"
              % (name, float(log(hl["rop"], 2)), claimed))
    print()
    return results


def main():
    print("LoongKEM sub-ring projection: lattice-estimator cost of projected MLWE")
    print("estimator repo:", EST)
    print()
    for spec in SETS:
        run_set(*spec)

    # Cross-validate Loong128 against the MEASURED noise from a REAL key
    # (src/project_loong.py reported sigma_e=4.58, sigma_s=2.81 on dump.txt).
    print("=" * 74)
    print("Loong128 CROSS-CHECK with MEASURED noise from a real key (dump.txt):")
    print("  sigma_e=4.58, sigma_s=2.81, n=208, m=192")
    p = LWE.Parameters(n=208, q=Q,
                       Xs=ND.DiscreteGaussian(2.81),
                       Xe=ND.DiscreteGaussian(4.58),
                       m=192, tag="Loong128-measured")
    r = LWE.primal_usvp(p, red_shape_model="gsa")
    print("  primal_usvp : rop=2^%.1f  beta=%s" % (float(log(r["rop"], 2)), r.get("beta")))


if __name__ == "__main__":
    main()
