# Exact DFR of UVW decryption with A retries of random info-set I1.
# e uniform weight w over F_q^n, split into n/2 pairs (e1_i,e2_i) in hidden coords.
# t=|e|_3 (e1=e2!=0), i=|e|_1 (exactly one nonzero), j=|e|_2 (both nonzero, different): w = i + 2j + 2t
# Clean-looking set I = pairs with e1-e2=0 : n/2 - i - j ; contains t bad pairs.
# per-attempt success s = C(|I|-t,k1)/C(|I|,k1)  (spec Thm 2 conditional)
from mpmath import mp, binomial as C, mpf, log
mp.dps=60
def run(q,n,k1,w,A_list=(1,10,100,1000)):
    h=n//2; tot=C(n,w)*mpf(q-1)**w
    single=mpf(0); fails={A:mpf(0) for A in A_list}; Pt={}
    for t in range(0,w//2+1):
        for i in range(0,w-2*t+1):
            if (w-2*t-i)%2: continue
            j=(w-2*t-i)//2
            if t+i+j>h: continue
            cnt=C(h,t)*C(h-t,i)*C(h-t-i,j)*(mpf(q-1))**t*(2*mpf(q-1))**i*(mpf(q-1)*(q-2))**j
            p=cnt/tot
            I=h-i-j
            if I<k1: s=mpf(0)
            else: s=C(I-t,k1)/C(I,k1)
            single+=p*s
            Pt[t]=Pt.get(t,0)+p
            for A in A_list: fails[A]+=p*(1-s)**A
    print(f"q={q} n={n} k1={k1} w={w}: single-attempt success={mp.nstr(single,8)}")
    for A in A_list: print(f"   DFR after {A:4d} attempts = {mp.nstr(fails[A],5)}  = 2^{mp.nstr(log(fails[A],2),5)}")
    for t in range(0,8): print(f"   P(|e|_3={t}) = 2^{mp.nstr(log(Pt[t],2),5)}")
run(433,860,215,116); run(857,1708,427,232); run(1709,3412,853,463)
