import numpy as np
rng=np.random.default_rng(1)
n=512; q=769; ND=128; k=4
# build m per code layout: group (i, b) = {ND*i + b + (ND//4)*t}, b in [0,ND//4)
nb=n//k
M=rng.integers(0,2,size=nb)
m=np.zeros(n,dtype=np.int64)
s=ND//4
gi=0
groups=[]
for i in range(n//ND):
    for b in range(s):
        pos=[ND*i+b+s*t for t in range(4)]
        groups.append(pos)
assert len(groups)==nb
for gidx,pos in enumerate(groups):
    while True:
        vals=rng.integers(0,2,size=8)  # a0,b0,...
        mt=[int(vals[2*t]-vals[2*t+1]) for t in range(4)]
        if (sum(mt)%2)==M[gidx]%2: break
    for t,p in enumerate(pos): m[p]=mt[t]
def negmul(a,b):
    c=np.zeros(2*n,dtype=np.int64)
    for i in np.nonzero(a)[0]:
        c[i:i+n]+=a[i]*b
    return c[:n]-c[n:]
vbar=np.zeros(n,dtype=np.int64)
for t in range(4): vbar[s*t]=1
u=negmul(vbar,m)
bad=0
for gidx,pos in enumerate(groups):
    for p in pos:
        if (u[p]-M[gidx])%2!=0: bad+=1
print("code layout, vbar stride",s,": parity violations",bad,"out of",n)
# now spec layout: stride n/k
s2=n//k
groups2=[[b+s2*t for t in range(4)] for b in range(s2)]
m2=np.zeros(n,dtype=np.int64)
for gidx,pos in enumerate(groups2):
    while True:
        vals=rng.integers(0,2,size=8)
        mt=[int(vals[2*t]-vals[2*t+1]) for t in range(4)]
        if (sum(mt)%2)==M[gidx]%2: break
    for t,p in enumerate(pos): m2[p]=mt[t]
vbar2=np.zeros(n,dtype=np.int64)
for t in range(4): vbar2[s2*t]=1
u2=negmul(vbar2,m2)
bad=0; mx=0
for gidx,pos in enumerate(groups2):
    for p in pos:
        if (u2[p]-M[gidx])%2!=0: bad+=1
        mx=max(mx,abs((u2[p]-M[gidx])//2))
print("spec layout, vbar stride",s2,": parity violations",bad,"max |e'|",mx)
