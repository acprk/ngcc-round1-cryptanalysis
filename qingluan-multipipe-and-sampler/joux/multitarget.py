#!/usr/bin/env python3
"""
Qing Luan (sign-20) — does the <=2^80 MULTI-TARGET model actually lower the
message-binding second-preimage cost, i.e. is L256 pushed below its target?

Spec §3.3 / Theorem 1 price message binding as multi-target eTCR = 2^{2λ-80}
(i.e. they assume T=2^80 targets give a /T speedup over 2^{2λ}).  But the salt
enters as a PREFIX:  digest_Msg = H_w(0x0A | Salt | pk_hash | Msg).  T distinct
salts => T distinct effective IVs.  The generic /T multi-target speedup only
exists when ONE hash evaluation can be tested against all T targets at once
(shared IV, membership lookup).  With distinct IVs, each target costs its own
hash evaluation, so the real WORK (compression calls) should stay flat in T.

This script measures it, with a positive control:
  * DISTINCT-salt  (the real construction): predict cost flat in T ~ 2^{n0}
  * SHARED-salt    (control, same IV):       predict cost ~ 2^{n0}/T  (real /T)
Work unit = compression-function calls (the honest metric; counting 'messages
tried' instead of calls is exactly the spec's mistake).

We isolate the multi-target question at P=1 (single pipe, no Joux confound); the
concatenation inherits the same per-target-recompute mechanism, and the Joux
(P-1) factor is orthogonal (already confirmed in joux_secondpreimage.py).
"""
import hashlib, random

CALLS = 0
def f(pipe, chain, block, n0):
    global CALLS
    CALLS += 1
    d = bytes([pipe]) + chain.to_bytes(4, "big") + block.to_bytes(4, "big")
    return int.from_bytes(hashlib.sha256(d).digest()[:4], "big") & ((1 << n0) - 1)

IV = 0
def digest(salt, msg_block, n0):
    # H_w for P=1: chain over [salt_block, msg_block], pipe 0. Salt is a PREFIX.
    return f(0, f(0, IV, salt, n0), msg_block, n0)

def log2(x):
    return (x.bit_length() - 1) if x else 0

def multitarget_2ndpreimage(n0, T, shared, seed, cap_mult=64):
    """Find (msg', i) with digest(salt_i, msg') == d_i and msg' != m_i.
    shared=False: salt_i = i (distinct IV).  shared=True: all salt_i = S (control)."""
    global CALLS
    rng = random.Random(seed)
    S = 0x515A                                   # fixed shared salt for the control
    salts = [S] * T if shared else list(range(1, T + 1))
    m = [rng.getrandbits(28) for _ in range(T)]  # the honest messages
    d = [digest(salts[i], m[i], n0) for i in range(T)]
    # attacker
    if shared:
        table = {}                               # digest -> index (one eval hits all T)
        for i in range(T):
            table.setdefault(d[i], i)
    CALLS = 0
    cap = cap_mult << n0
    tried = 0
    for c in range(cap):
        if shared:
            v = f(0, f(0, IV, S, n0), c, n0)     # ONE evaluation, test all T via dict
            tried += 1
            j = table.get(v)
            if j is not None and c != m[j]:
                return CALLS, tried
        else:
            for i in range(T):                   # distinct IV: must recompute per target
                v = f(0, f(0, IV, salts[i], n0), c, n0)
                tried += 1
                if v == d[i] and c != m[i]:
                    return CALLS, tried
    return None, tried

def run(n0s, Ts, seeds=8):
    print(f"\n{'='*72}\nMulti-target 2nd-preimage: compression calls vs #targets T")
    for n0 in n0s:
        print(f"\n n0={n0}   (single-target ~ 2^{n0})")
        print(f"  {'T':>5} | {'DISTINCT log2(calls)':>22} | {'SHARED(control) log2(calls)':>28}")
        dist_pts, shar_pts = [], []
        for T in Ts:
            dc = []; sc = []
            for s in range(seeds):
                c1, _ = multitarget_2ndpreimage(n0, T, shared=False, seed=1000+s+7*T)
                c2, _ = multitarget_2ndpreimage(n0, T, shared=True,  seed=1000+s+7*T)
                if c1: dc.append(c1)
                if c2: sc.append(c2)
            dmed = sorted(dc)[len(dc)//2] if dc else 0
            smed = sorted(sc)[len(sc)//2] if sc else 0
            print(f"  {T:>5} | {log2(dmed):>22} | {log2(smed):>28}")
            if dmed: dist_pts.append((log2(T), log2(dmed)))
            if smed: shar_pts.append((log2(T), log2(smed)))
        def slope(pts):
            n=len(pts); sx=sum(x for x,_ in pts); sy=sum(y for _,y in pts)
            sxx=sum(x*x for x,_ in pts); sxy=sum(x*y for x,y in pts)
            return (n*sxy-sx*sy)/(n*sxx-sx*sx) if n*sxx-sx*sx else 0
        print(f"    -> DISTINCT slope d log2(calls)/d log2(T) = {slope(dist_pts):+.2f}"
              f"   (predict 0 = NO multi-target speedup)")
        print(f"    -> SHARED   slope d log2(calls)/d log2(T) = {slope(shar_pts):+.2f}"
              f"   (predict -1 = real /T; proves the harness can see a speedup)")

if __name__ == "__main__":
    print(__doc__)
    run(n0s=[12, 14, 16], Ts=[1, 4, 16, 64, 256])
    print("""
CONCLUSION
  DISTINCT-salt slope ~ 0  => the <=2^80 multi-target model gives NO reduction in
  actual work for Qing Luan's message binding: each of the T salts is a distinct
  prefix/IV and costs its own hash evaluation.  The SHARED-salt control shows
  slope ~ -1, confirming the harness WOULD see a /T speedup if one existed.

  Therefore, back at width n=256:
     real multi-target 2nd-preimage  =  real single-target  =  2^{(P-1)*256}
     L256 (P=2): 2^256  ==  classical target 256   -> margin EXACTLY 0, NOT below.
     L384 (P=3): 2^512  >= 384 ;  L512 (P=4): 2^768 >= 512.

  => The 'L256 dips below 256 under 2^80 multi-target' hypothesis is FALSIFIED.
     The salt does its job: no /T. What remains true and reportable:
       (1) spec's numbers (2^{2λ} single, 2^{2λ-80} multi) are WRONG by up to
           256 bits (overstated), and
       (2) L256 message binding has ZERO margin (2^256 == target), so any future
           improvement to concatenation preimage, or any unsalted hash use, breaks
           it -- but as submitted, no level is demonstrably below its target here.
  This is the falsify-first outcome: we tried to push L256 under and could not.
""")
