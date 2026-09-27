# Re-confirm the sub-ring projection on the REAL Cheetah128 key (public a,b + secret for checking).
q=7681; N=640; d=128; assert N//d==5 and N%d==0
def rd(name):
    for line in open('dump1.txt'):
        t=line.split()
        if t and t[0]==name: return [int(x) for x in t[1:]]
    return None
a=rd('a_coef'); s=rd('s_coef'); b=rd('b_tilde')
def cent(x): x%=q; return x-q if x>q//2 else x
def psi(c):  # R_640 -> R_128 negacyclic
    o=[0]*d
    for j in range(N):
        o[j%d]=(o[j%d]+((-1)**(j//d))*c[j])%q
    return o
def negconv(x,y,n):  # negacyclic product mod X^n+1
    o=[0]*n
    for i in range(n):
        for j in range(n):
            k=i+j; o[k%n]=(o[k%n]+((-1 if k>=n else 1))*x[i]*y[j])%q
    return o
pa,ps,pb=psi(a),psi(s),psi(b)
prod=negconv(pa,ps,d)
# identity: psi(b - a*s) == psi(b) - psi(a)*psi(s)
as_full=negconv(a,s,N)
lhs=psi([(b[i]-as_full[i])%q for i in range(N)])
rhs=[(pb[i]-prod[i])%q for i in range(d)]
print("ring-hom identity psi(b-a*s)==psi(b)-psi(a)psi(s):", lhs==rhs)
noise=[cent((pb[i]-prod[i])%q) for i in range(d)]
ss=[cent(x) for x in ps]
import statistics as st
print(f"projected noise psi(e+delta): max|.|={max(abs(x) for x in noise)}  sigma={st.pstdev(noise):.2f}  (model sigma~6.38)")
print(f"projected secret psi(s):      max|.|={max(abs(x) for x in ss)}     sigma={st.pstdev(ss):.2f}  (model sigma~3.54)")
print(f"=> projected instance is a valid n={d}, q={q} LWE with small secret+noise: decision-SLWE broken.")
