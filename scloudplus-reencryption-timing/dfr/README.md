# DFR proof gap (spec Sec. 3.1.4 / Table 16 is not a ball-failure upper bound)

`dfr_model.py` is self-contained pure Python (numpy, scipy, mpmath); it needs no vendor code. It
computes the block decryption-failure probability under the spec's own ball criterion
`||eps_block|| >= R` with three models and prints log2(DFR):

  A  spec Sec. 3.1.4: i.i.d. continuous Gaussian coordinate marginal (Gamma tail).
     Reproduces Table 16 to <=0.1 bit (engine control: feeding A a Gaussian pmf reproduces A to 0.01 bit).
  B  i.i.d. coordinates with the EXACT marginal: each coordinate is a sum of 2(m+n) independent
     {-1,0,1} products plus one BD_e term; tail of the sum of d squares by exact convolution.
  C  key-conditional Gaussian: given (S,E) a noise row is N(0, Vs E^T E + Ve S^T S + Ve I),
     keeping key variation AND within-row correlation from the shared S'_i/E1_i; averaged over keys.

Run:  python3 dfr_model.py

Result (our run): the A column equals Table 16 (-138.5/-220.9/-271.8/-457.7/-552.6). The exact
marginal (B) and the key-conditional model (C) are HEAVIER than the spec Gaussian, most at L512:

  L     A (=Table16)   B (exact iid)   C (key-cond mean)   B-A     C-A
  128   -138.5         -137.9          -132.5              +0.7    +6.0
  192   -220.9         -220.7          -214.3              +0.2    +6.6
  256   -271.9         -269.9          -262.6              +2.0    +9.3
  384   -457.8         -454.5          -441.8              +3.3    +16.0
  512   -552.6         -518.1          -524.6              +34.5   +28.1

So both non-conservative approximations (Gaussian marginal; block-coordinate independence - the LAC
effect, D'Anvers-Vercauteren-Verbauwhede ePrint 2018/1172) push the ball bound up. At L512 the
margin over 2^-512 collapses from ~40 bits (spec) to single digits; a fully conservative combination
of the two corrections no longer certifies DFR < 2^-512 by the spec's method. This is a proof gap,
not a demonstrated failure: the ball bound is itself very pessimistic for this decoder (at measurable
depth the BDD corrects 99%+ of outside-ball errors), so no real DFR violation is shown.
