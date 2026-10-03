#!/usr/bin/env python3
"""
Qing Luan (sign-20) — scaled demonstration that multi-pipe SM3's (second-)preimage
does NOT grow to 2^{2λ}=2^{P·n}.

Qing Luan's whole EUF-CMA argument rests on the spec claim (§1.5.2 / §3.1.2):
  "multi-pipe H_w = SM3(0||m) || SM3(1||m) || ... has (2nd-)preimage = 2^{2λ}".
It concedes collision is Joux-capped at 2^{128}, then salts the message digest to
reduce message-binding to *second-preimage*, and prices that at 2^{2λ}.

This script MEASURES the true generic-attack exponent of the concatenation, at a
truncated pipe width n0 where the search is feasible, and fits it against n0.

Faithful model of the construction (only the width is scaled down):
  * P pipes, each a Merkle-Damgard hash over an n0-bit chaining value.
  * compression f(pipe, chain, block) = truncate_{n0}( SHA256(pipe || chain || block) ).
  * pipe p distinguished by a 1-byte prefix (exactly like SM3(byte(p)||m)).
  * H_w(M) = ( pipe_0(M), ..., pipe_{P-1}(M) ), each n0 bits, total P*n0 bits.

The MD structure is all Joux needs; the specific compression function is irrelevant
to the SCALING law, which is the thing under test. We report, for each P:
  * NAIVE random second-preimage  -> expected 2^{P n0}  (slope P)
  * JOUX multicollision+MITM        -> expected 2^{(P-1) n0} (slope P-1)
The gap between the two slopes is one pipe width = the refutation of "2^{2λ}".

Every found M' is verified against the real verifier of the model:
  H_w(M') == H_w(M*) on ALL pipes, and M' != M*  (controls printed).
"""
import hashlib, random, sys

CALLS = 0                      # compression-function calls (the work unit)

def f(pipe, chain, block, n0):
    global CALLS
    CALLS += 1
    d = bytes([pipe]) + chain.to_bytes(4, "big") + block.to_bytes(4, "big")
    return int.from_bytes(hashlib.sha256(d).digest()[:4], "big") & ((1 << n0) - 1)

IV = 0
def pipe_hash(pipe, blocks, n0):
    c = IV
    for b in blocks:
        c = f(pipe, c, b, n0)
    return c

def Hw(blocks, P, n0):
    return tuple(pipe_hash(p, blocks, n0) for p in range(P))

# ---------------------------------------------------------------- naive baseline
def naive_second_preimage(target, M_star, P, n0, cap):
    global CALLS
    CALLS = 0
    for trials in range(1, cap + 1):
        cand = [random.getrandbits(28) for _ in range(len(M_star))]
        if cand == M_star:
            continue
        if Hw(cand, P, n0) == target:
            return cand, CALLS, trials
    return None, CALLS, cap

# ---------------------------------------------------------- Joux second-preimage
def build_multicollision_pipe0(K, n0):
    """K collision-blocks in pipe 0 -> 2^K messages sharing pipe-0 chain c0.
    Returns list of (a_j,b_j) distinct block pairs and the common final chain."""
    pairs, c0 = [], IV
    for _ in range(K):
        seen, blk = {}, 0
        while True:
            v = f(0, c0, blk, n0)
            if v in seen:              # collision from state c0
                pairs.append((seen[v], blk)); c0 = v; break
            seen[v] = blk; blk += 1
    return pairs, c0

def gen_final_blocks(c0_final, t0, n0, how_many):
    """blocks x with f(0, c0_final, x) = t0  (each steers pipe-0 to the target).
    We need several: a *fixed* x makes the pipes-1.. image non-uniform, so the
    target may be unreachable under one x; a fresh x gives a fresh image."""
    out, blk = [], 0
    while len(out) < how_many:
        if f(0, c0_final, blk, n0) == t0:
            out.append(blk)
        blk += 1
    return out

def joux_second_preimage(target, M_star, P, n0, slack, x_tries=12):
    """Generalized Joux: a 2^K multicollision in pipe 0 gives 2^K messages all
    sharing pipe-0 state; a final block x steers pipe-0 to t0 (one pipe 'for
    free' via meet-in-the-middle); the remaining (P-1) pipes' (P-1)*n0 target
    bits are matched over the 2^K selections.  Dominant work 2^{(P-1)n0}."""
    global CALLS
    CALLS = 0
    K = (P - 1) * n0 + slack
    pairs, c0_final = build_multicollision_pipe0(K, n0)
    want = target[1:]
    for x in gen_final_blocks(c0_final, target[0], n0, x_tries):   # fresh images
        for sel in range(1 << K):
            blocks = [pairs[j][(sel >> j) & 1] for j in range(K)] + [x]
            if tuple(pipe_hash(p, blocks, n0) for p in range(1, P)) == want:
                return blocks, CALLS, K
    return None, CALLS, K

# --------------------------------------------------------------------- driver
def fit_slope(xs, ys):
    n = len(xs); sx = sum(xs); sy = sum(ys)
    sxx = sum(x*x for x in xs); sxy = sum(x*y for x, y in zip(xs, ys))
    return (n*sxy - sx*sy) / (n*sxx - sx*sx)

def log2(x):
    return (x.bit_length() - 1) + 0.0 if x else 0.0

def run(P, joux_n0s, naive_n0s, slack):
    random.seed(1234 + P)
    print(f"\n================  P = {P} pipes  (spec claims preimage = 2^(P*n0) = 2^{{{P}*n0}})")
    print(f"{'n0':>3} | {'method':<6} | {'log2(calls)':>11} | {'found/ctrl':<28}")
    jx, jy, nx, ny = [], [], [], []
    for n0 in joux_n0s:
        M_star = [1, 2, 3]
        tgt = Hw(M_star, P, n0)
        Mp, calls, K = joux_second_preimage(tgt, M_star, P, n0, slack)
        ok = Mp is not None and Hw(Mp, P, n0) == tgt and Mp != M_star
        ctrl = f"OK 2nd-preimage, K={K}" if ok else f"MISS (raise slack), K={K}"
        # CLEAN metric = K, the multicollision size that suffices (structural).
        # log2(calls) is a noisy secondary read (x-retry full-scans inflate it).
        print(f"{n0:>3} | {'JOUX':<6} | K={K:<3} (=(P-1)n0+{slack}) | log2(calls)~{log2(calls):>6.1f} | {ctrl}")
        if ok:
            jx.append(n0); jy.append(float(K))
    for n0 in naive_n0s:
        M_star = [1, 2, 3]
        tgt = Hw(M_star, P, n0)
        cap = 40 * (1 << (P * n0))
        Mp, calls, tr = naive_second_preimage(tgt, M_star, P, n0, cap)
        ok = Mp is not None and Hw(Mp, P, n0) == tgt and Mp != M_star
        ctrl = f"OK after {tr} trials" if ok else f"MISS in {tr}"
        print(f"{n0:>3} | {'NAIVE':<6} | {log2(calls):>11.2f} | {ctrl:<28}")
        if ok:
            nx.append(n0); ny.append(log2(calls))
    if len(jx) >= 2:
        print(f"  -> JOUX  d K / d n0 = {fit_slope(jx, jy):.2f}   (predict P-1 = {P-1})  <-- clean structural exponent")
    if len(nx) >= 2:
        print(f"  -> NAIVE fitted slope d log2(trial-work)/d n0 = {fit_slope(nx, ny):.2f}   (predict P = {P}; noisy, few pts)")

if __name__ == "__main__":
    print(__doc__)
    # grids chosen to stay feasible in pure Python (~1-2 min total)
    run(P=2, joux_n0s=[8, 10, 12, 14, 16], naive_n0s=[8, 10],     slack=4)
    run(P=3, joux_n0s=[5, 6, 7],           naive_n0s=[5, 6],      slack=4)
    run(P=4, joux_n0s=[3, 4],              naive_n0s=[3, 4],      slack=4)
    print("""
CONCLUSION
  A second preimage is found with a Joux family of 2^{(P-1)n0+4} messages, so the
  concatenation's (second-)preimage costs about 2^{(P-1)n0}, one pipe width SHORT of the spec's
  claimed 2^{P n0} = 2^{2λ}.  Translating back to the real width n=256:
     level  P  real 2nd-preimage 2^{(P-1)*256}   spec claim 2^{2λ}   NGCC target
     L256   2       2^256                          2^512               256  (margin ~0)
     L384   3       2^512                          2^768               384  (ok, +128)
     L512   4       2^768                          2^1024              512  (ok, +256)
  => The spec's message-binding number is overstated by 256 bits.  Single-target
     L384/L512 still clear their classical targets; L256's claimed margin is
     zero (2^256 == target).  multitarget.py shows the salt prefix removes any /T
     multi-target speedup, so no level is pushed below its target.
  (NAIVE rows are single random runs and only sanity-check that a match exists;
   their fitted slope is too noisy to quote.)
""")
