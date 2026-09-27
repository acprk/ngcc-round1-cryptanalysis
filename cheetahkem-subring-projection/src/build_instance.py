# Build the REAL Cheetah128 projected LWE from dump1.txt. Secret read ONLY to score.
import statistics as st
q=7681; N=640; d=128
def rd(name):
    for line in open('dump1.txt'):
        t=line.split()
        if t and t[0]==name: return [int(x) for x in t[1:]]
def cent(x):
    x%=q; return x-q if x>q//2 else x
def psi(c):
    o=[0]*d
    for j in range(N):
        o[j%d]=(o[j%d]+((-1)**(j//d))*c[j])%q
    return o
a=rd('a_coef'); s=rd('s_coef'); b=rd('b_tilde')
pa=psi(a); pb=psi(b); ps=[x%q for x in psi(s)]   # ps only for scoring
# A_proj: (pa*ps)[m] = sum_j A[m][j] ps[j], negacyclic mod X^128+1
A=[[0]*d for _ in range(d)]
for m in range(d):
    for j in range(d):
        if j<=m: A[m][j]= pa[m-j]%q
        else:    A[m][j]= (-pa[m+d-j])%q
# check: A@ps == pb - e ; recover e, check stats
Aps=[sum(A[m][j]*ps[j] for j in range(d))%q for m in range(d)]
e=[cent((pb[m]-Aps[m])%q) for m in range(d)]
print("max|e_proj|=",max(abs(x) for x in e)," sigma=",round(st.pstdev(e),2)," (model ~6.38)")
print("secret sigma=",round(st.pstdev([cent(x) for x in ps]),2)," (model ~3.54)")
# save instance (A, b=pb) and secret (for scoring) 
import json
json.dump({'q':q,'n':d,'A':A,'b':[x%q for x in pb],'s_score':[cent(x) for x in ps],'e_score':e},
          open('cheetah128_proj.json','w'))
print("wrote cheetah128_proj.json  (n=128, q=7681)")
