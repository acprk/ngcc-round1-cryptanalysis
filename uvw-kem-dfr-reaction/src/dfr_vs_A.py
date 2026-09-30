from mpmath import mp, binomial as C, mpf, log
mp.dps=50
q,n,k1,w=433,860,215,116; h=n//2; tot=C(n,w)*mpf(q-1)**w
rows=[]
for t in range(0,40):
    for i in range(0,w-2*t+1):
        if (w-2*t-i)%2: continue
        j=(w-2*t-i)//2
        if t+i+j>h: continue
        p=C(h,t)*C(h-t,i)*C(h-t-i,j)*(mpf(q-1))**t*(2*mpf(q-1))**i*(mpf(q-1)*(q-2))**j/tot
        I=h-i-j; s=C(I-t,k1)/C(I,k1) if I>=k1 else mpf(0)
        rows.append((p,s))
for A in [10**3,10**4,10**5,10**6,10**8,10**10]:
    F=sum(p*(1-s)**A for p,s in rows)
    print(f"A=1e{len(str(A))-1}: DFR=2^{mp.nstr(log(F,2),4)}")
