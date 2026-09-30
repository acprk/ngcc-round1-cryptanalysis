import random, re, math, sys
# usage: tcount.py /path/to/Reference_Implementation   (reads each set's parameters.h)
import glob, os
P={}
root=sys.argv[1] if len(sys.argv)>1 else '.'
for f in glob.glob(os.path.join(root,'ReSolveD-alpha-*','parameters.h')):
    for line in open(f):
        m=re.match(r'#define RESOLVED_ALPHA_(\w+?)_(CSP|TAU|POW_LEVEL|T_OPEN) (\d+)',line)
        if m: P.setdefault(m.group(1),{})[m.group(2)]=int(m.group(3))
if not P: sys.exit('no parameters.h found under '+root)
def sim(p,trials=4000,rng=random.Random(1)):
    lam,tau,w,To=p['CSP'],p['TAU'],p['POW_LEVEL'],p['T_OPEN']
    k=(lam-w)//tau+1; tau1=(lam-w)%tau; tau0=tau-tau1
    L=tau1*(1<<k)+tau0*(1<<(k-1))
    def pos(i,j):
        tmp=1<<(k-1)
        if j<tmp: return L-1+tau*j+i
        return L-1+tau*tmp+tau1*(j&(tmp-1))+i
    Ts=[];rej=0
    while len(Ts)<trials:
        s=set(); nh=0
        for i in range(tau):
            N = (1<<k) if i<tau1 else (1<<(k-1))
            a=pos(i,rng.randrange(N)); s.add(a); nh+=1
            while a>0 and ((a-1)//2) not in s:
                a=(a-1)//2; s.add(a); nh+=1
        T=nh-2*tau+1
        if T>To: rej+=1; continue
        Ts.append(T)
    Ts.sort()
    return lam,tau,k,L,To,min(Ts),Ts[len(Ts)//2],max(Ts),sum(math.log2(t) for t in Ts)/len(Ts),rej/(rej+len(Ts))
print("set      lam tau k   L      Topen  T_min T_med T_max  E[log2T]  P(reject)")
for n,p in sorted(P.items(), key=lambda x:(x[1]['CSP'],x[0])):
    r=sim(p)
    print(f"{n:6s} {r[0]:4d} {r[1]:3d} {r[2]:2d} {r[3]:6d} {r[4]:5d} {r[5]:5d} {r[6]:5d} {r[7]:5d}   {r[8]:.2f}   {r[9]:.3f}")
