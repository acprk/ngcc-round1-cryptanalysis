# Angles we checked and refuted (recorded so others need not repeat them)

Build these against a vendor set, e.g.
`d=$REF/Reference_Implementation/lwekem128; gcc-11 -O2 -w -I$d <file> $d/minal.c $d/reduce.c -lm -o t`.

## Decoder optimality — the shipped 2D-B2-Minal decoder is effectively ML-optimal (DFR claim not undermined)
- `mlcheck.c`: exhaustively compares the shipped `minal_b2_code_decode` to a maximum-likelihood
  nearest-codeword decoder over ALL (x,y) in [0,q)^2. They differ on only 0.087% (128-I) / 0.038%
  (512-I) of the grid, and all such points lie far out between codewords (distance >> the packing
  radius), never reached by honest small noise.
- `chan.c`: Gaussian-channel sweep (2e6 trials per sigma). Shipped-decoder and ML-decoder failure
  rates are identical to two decimals (ratio 1.00) across the whole honest-noise range; at the
  sigma where honest decoding lives, both give 0 failures. So the shipped decoder loses no bits
  versus an optimal-decoder DFR model — the authors' DFR (which we reproduced exactly from their
  shipped mpfr code elsewhere) is not undermined by decoder sub-optimality.

## Constant-time — the reference decode path is constant-time
Verified separately (gcc-11 + clang, -O2/-Os disassembly of minal.c/poly.c/reduce.c): every
conditional jump in `minal_b2_code_decode` is a fixed-count loop bound or the stack canary; all
secret-data ops are cmov/setcc/imul; no secret-indexed memory; 0 idiv (no KyberSlash). `freeze()`
has only a debug `assert` branch that vanishes under -DNDEBUG. The two `centered_mod_i16` variants
(128/256 vs 512) differ at exactly one input a=q/2 but never change a decode output — harmless.
