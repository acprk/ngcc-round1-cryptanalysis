# failure boosting: attacker grinds m offline so that e=H1(m) has |e|_3 >= T (checkable? NO: hidden pairs unknown!)
# => attacker cannot compute |e|_3 without the key. So grinding is blind: only random ciphertexts. Report P(fail|t) and
# the cost per observed final ⊥ with random honest-looking ciphertexts.
from mpmath import mp, binomial as C, mpf, log
mp.dps=50
def run(q,n,k1,w,A=1000):
    h=n//2; tot=C(n,w)*mpf(q-1)**w
    byt={}
    for t in range(0,12):
        for i in range(0,w-2*t+1):
            if (w-2*t-i)%2: continue
            j=(w-2*t-i)//2
            if t+i+j>h: continue
            p=C(h,t)*C(h-t,i)*C(h-t-i,j)*(mpf(q-1))**t*(2*mpf(q-1))**i*(mpf(q-1)*(q-2))**j/tot
            I=h-i-j; s=C(I-t,k1)/C(I,k1) if I>=k1 else mpf(0)
            a=byt.setdefault(t,[mpf(0),mpf(0),mpf(0)]); a[0]+=p; a[1]+=p*(1-s)**A; a[2]+=p*s
    print(f"n={n}:")
    for t in range(1,9):
        P,F,S=byt[t]; print(f"  t={t}: P(t)=2^{mp.nstr(log(P,2),4)}  mean s=1/{mp.nstr(P/S,4)}  P(fail after {A}|t)={mp.nstr(F/P,4)}  contrib 2^{mp.nstr(log(F,2),4) if F>0 else '-inf'}")
run(433,860,215,116); run(857,1708,427,232); run(1709,3412,853,463)
