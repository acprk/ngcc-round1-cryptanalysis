# Simulate the reaction statistic using only FINAL decapsulation failures (after 1000 retries).
# Failing ciphertexts are drawn from the exact conditional law: t ~ P(t|fail) (dominated by t=4..7),
# t hidden pairs with e[a]=gamma*e[b]!=0, remaining weight random with no extra equal pairs.
import numpy as np, sys
rng=np.random.default_rng(1)
q,n,w=433,860,116
h=n//2
perm=rng.permutation(n); A=perm[:h]; B=perm[h:]
d=rng.integers(1,q,size=n)
inv=lambda x: pow(int(x),q-2,q)
gamma=np.array([d[A[i]]*inv(d[B[i]])%q for i in range(h)])
partner=np.empty(n,int); partner[A]=B; partner[B]=A
# P(t|fail) for UVW128 from boost.py contributions (t=4..8)
ts=np.array([4,5,6,7,8]); lw=np.array([-47.84,-43.46,-47.58,-54.86,-63.42]); pt=2.0**lw; pt/=pt.sum()
def sample():
    t=rng.choice(ts,p=pt)
    e=np.zeros(n,int)
    pairs=rng.choice(h,size=t,replace=False)
    for p in pairs:
        v=int(rng.integers(1,q)); e[B[p]]=v; e[A[p]]=gamma[p]*v%q
    rest=w-2*t
    free=np.setdiff1d(np.arange(n),np.concatenate([A[pairs],B[pairs]]))
    pos=rng.choice(free,size=rest,replace=False)
    e[pos]=rng.integers(1,q,size=rest)
    # remove accidental extra equal pairs (prob ~2%): re-randomize
    for a in pos:
        b=partner[a]
        if e[b] and ((a in A and e[a]==gamma[np.where(A==a)[0][0]]*e[b]%q) ): e[a]=(e[a]%(q-1))+1
    return e
invtab=np.array([0]+[inv(x) for x in range(1,q)])
def keys(e):
    s=np.nonzero(e)[0]; a,b=np.triu_indices(len(s),1); a=s[a]; b=s[b]
    r=e[a]*invtab[e[b]]%q
    return (a*n+b)*q+r
truth=set()
for i in range(h):
    a,b=A[i],B[i]; r=gamma[i]
    if a>b: a,b=b,a; r=inv(r)
    truth.add((a*n+b)*q+r)
for N in [int(x) for x in sys.argv[1:]]:
    ks=np.concatenate([keys(sample()) for _ in range(N)])
    u,c=np.unique(ks,return_counts=True)
    order=np.argsort(-c)
    # greedy partition: take highest counts, keep if both coords unused
    used=set(); got=[]
    for idx in order:
        k=int(u[idx]); ab=k//q; a,b=ab//n,ab%n
        if a in used or b in used: continue
        used.add(a); used.add(b); got.append(k)
        if len(got)==h: break
    ok=sum(k in truth for k in got)
    tc=[c[i] for i in range(len(u)) if int(u[i]) in truth]
    print(f"N={N} failures: true-triple mean count={np.mean(tc) if tc else 0:.2f} (seen {len(tc)}/{h}), max false={max(c[i] for i in order[:5000] if int(u[i]) not in truth)}, greedy partition exact={ok}/{h}",flush=True)
