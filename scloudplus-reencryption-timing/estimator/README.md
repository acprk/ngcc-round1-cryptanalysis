# L512 light-key dual hybrid: T/eps below 512 (metric-dependent, not a practical threat)

Requires SageMath and the lattice-estimator. Point ESTIMATOR at a lattice-estimator checkout
(commit 5ba00f5 in our runs):

    ESTIMATOR=/path/to/lattice-estimator \
      sage -python weak_key_scan.py 512 CoreSVP 180 300 4 ejk

The Scloud+-512 secret is i.i.d. BD(1/12), NOT fixed-weight (mean weight 366.7, sd 17.6). A
cost/advantage (T/eps) adversary can target the light keys: for total weight h it attacks
SparseTernary(h/2,h/2,n) with the sparse dual hybrid at cost T(h), and pays advantage
eps = Pr[W <= h] under the real i.i.d. weight distribution; the effective work is log2 T(h) - log2 eps,
minimized over h.

Expected output (our runs; the script prints the minimizing h and the work):
  - CoreSVP:  T/eps = 2^490.8 (stock estimator) / 2^487.6 (exact i.i.d. re-implementation)
  - MATZOV22: 2^504.5 / 2^501.2
  - CoreSVP quantum: 2^469.3 / 2^466.3   (>> the 256-bit quantum target)
Both classical numbers are 21-24 bits below the claimed 512. Status: CONFIRMED as an estimator
computation but metric-dependent and not practical (still 2^488): the primal hybrid with the same
weak-key trick bottoms out at 2^555.8 (> 512), and under the standard metric (a typical key,
success ~1) no level falls below its claim. Levels 128/192/256/384 are unaffected (their binding
attack, MATZOV22 dual hybrid, gains nothing from lighter keys). Proposed as a level-overestimate
note (still >= the next NGCC level 384), not a break.
