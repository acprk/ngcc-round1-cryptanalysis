# Toy QuickSilver (VOLE-in-the-head) check for ONE degree-d constraint over GF(2^8),
# same algebra as SYDO's RSD.Prove/RSD.Verify: MACs  m_i = v_i + w_i*Delta,
# verifier evaluates f on MACs -> polynomial in Delta whose top coefficient is f(w).
# Honest: f(w)=0 and the prover's d coefficients a_0..a_{d-1} make the check pass for all Delta.
# Cheater: f(w)=e!=0; it picks d target Deltas in advance and adjusts a_k so the check
# passes exactly on those d values  =>  soundness error d/|Delta-space|, i.e. the -log2(d)
# term in SYDO's own inequality.  With the implemented grinding (wgrind-log2 d bits)
# the forgery cost is 2^(lambda - log2 d).
import random, itertools
def gmul(a,b):
    r=0
    while b:
        if b&1: r^=a
        b>>=1; a<<=1
        if a&0x100: a^=0x11B
    return r
def gpow(a,e):
    r=1
    for _ in range(e): r=gmul(r,a)
    return r
d=4
def f(x):   # degree-4 constraint of SYDO's block-1 membership type: x0*x1*x2*x3 (must be 0)
    r=1
    for t in x: r=gmul(r,t)
    return r
def polymul(p,q):
    r=[0]*(len(p)+len(q)-1)
    for i,a in enumerate(p):
        for j,b in enumerate(q): r[i+j]^=gmul(a,b)
    return r
def run(w, cheat_targets=None):
    v=[random.randrange(256) for _ in w]
    # prover side: f(v + w*X) as polynomial in X (coeffs low->high), computed symbolically
    P=[1]
    for vi,wi in zip(v,w): P=polymul(P,[vi,wi])
    e=P[d]                       # = f(w)
    a=P[:d]                      # honest proof coefficients a_0..a_{d-1}
    if cheat_targets:
        Z=[1]
        for t in cheat_targets: Z=polymul(Z,[t,1])        # prod (X - t), char 2
        a=[a[k]^gmul(e,Z[k]) for k in range(d)]           # so e*X^d + sum a_k X^k - P == e*Z(X)
    passed=[]
    for D in range(256):
        m=[vi^gmul(wi,D) for vi,wi in zip(v,w)]            # verifier's MACs
        lhs=f(m)
        rhs=0
        for k in range(d): rhs^=gmul(a[k],gpow(D,k))
        if cheat_targets: rhs^=gmul(e,gpow(D,d))*0          # cheater claims f(w)=0 (no X^d term)
        if lhs==rhs: passed.append(D)
    return e,passed
random.seed(1)
e,p=run([1,0,1,1]);           print("honest  f(w)=%d  passing Deltas: %d/256"%(e,len(p)))
e,p=run([1,1,1,1]);           print("false   f(w)=%d  no cheating     : %d/256 pass"%(e,len(p)))
T=[3,77,150,201]
e,p=run([1,1,1,1],T);         print("false   f(w)=%d  cheat on %s: passing Deltas=%s"%(e,T,p))
