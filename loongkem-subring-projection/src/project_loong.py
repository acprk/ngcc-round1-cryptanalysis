#!/usr/bin/env python
"""Verify the sub-ring (CRT) projection on real Loong128 keys.
Confirms: (1) b1 = A1 s1 + A2 s2 + e1 in R=Z_q[X]/(X^12+1) with small e1;
(2) psi: R -> R_4 = Z_q[X]/(X^4+1) is a ring hom mapping the STRUCTURED rows to
a genuine small-noise MLWE instance; (3) the projection uses only A1,A2,b1 and
never the unstructured A4/B2 block.
Usage: sage -python project_loong.py <dump.txt>
"""
import sys

def read_dump(path):
    d = {}
    for line in open(path):
        line=line.strip()
        if not line or line.startswith('#'): continue
        k, _, rest = line.partition(' ')
        rest = rest.strip()
        if k in ('N', 'K1', 'K2', 'Q', 'ETA', 'DB'):
            d[k] = int(rest)
        else:
            d[k] = [int(t) for t in rest.split()]
    return d

def negmul(a, b, n, q):
    c = [0]*(2*n-1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                c[i+j] += ai*bj
    return [(c[i] - (c[i+n] if i+n < 2*n-1 else 0)) % q for i in range(n)]

def psi(f, n, dd, q=None):
    out=[0]*dd
    for i,fi in enumerate(f):
        out[i%dd]+= (-fi if ((i//dd)%2) else fi)
    return [v%q for v in out] if q is not None else out

def center(v,q): return [(x+q//2)%q - q//2 for x in v]
def var(v):
    m=sum(v)/len(v); return sum((x-m)**2 for x in v)/len(v), m

def main():
    d=read_dump(sys.argv[1]); N=d['N']; K1=d['K1']; K2=d['K2']; q=d['Q']; eta=d['ETA']
    A1=d['A1']; A2=d['A2']; s1=d['s1']; s2=d['s2']; b1=d['b1']
    def poly(vec,idx): return vec[idx*N:(idx+1)*N]
    # e1[row] = b1[row] - sum_c A1[row,c] s1[c] - sum_c A2[row,c] s2[c]
    e1=[]
    for row in range(K1):
        acc=[0]*N
        for col in range(K1):
            p=negmul(poly(A1,row*K1+col), poly(s1,col), N, q)
            acc=[(acc[i]+p[i])%q for i in range(N)]
        for col in range(K2):
            p=negmul(poly(A2,row*K2+col), poly(s2,col), N, q)
            acc=[(acc[i]+p[i])%q for i in range(N)]
        e1.append(center([(b1[row*N+i]-acc[i])%q for i in range(N)],q))
    flat_e=[x for r in e1 for x in r]
    ve,_=var(flat_e)
    print('full-ring residual e1=b1-(A1 s1+A2 s2): max|.|=%d var=%.2f (model eta/2+2^%d/12=%.2f)'
          %(max(abs(x) for x in flat_e), ve, 13-d['DB'], eta/2.0+(2**(13-d['DB']))**2/12.0))

    # projection to R_4
    dd=4
    # ring-hom check: psi(e1) two ways
    ok=True; proj_e=[]
    for row in range(K1):
        acc=[0]*dd
        for col in range(K1):
            p=negmul(psi(poly(A1,row*K1+col),N,dd,q), psi(poly(s1,col),N,dd,q), dd, q)
            acc=[(acc[i]+p[i])%q for i in range(dd)]
        for col in range(K2):
            p=negmul(psi(poly(A2,row*K2+col),N,dd,q), psi(poly(s2,col),N,dd,q), dd, q)
            acc=[(acc[i]+p[i])%q for i in range(dd)]
        pe=center([(psi(b1[row*N:(row+1)*N],N,dd,q)[i]-acc[i])%q for i in range(dd)],q)
        pe2=psi(e1[row],N,dd)
        if any((pe[i]-pe2[i])%q for i in range(dd)): ok=False
        proj_e+=pe
    print('ring-hom check psi(b1-As)==psi(b1)-psi(A)psi(s):', ok)
    vpe,_=var(proj_e)
    print('projected noise psi(e1): max|.|=%d var=%.2f sigma=%.2f (model x N/d=%d -> %.2f)'
          %(max(abs(x) for x in proj_e), vpe, vpe**.5, N//dd, (N//dd)*(eta/2.0+(2**(13-d['DB']))**2/12.0)))
    sp=[psi(poly(s1,c),N,dd) for c in range(K1)]+[psi(poly(s2,c),N,dd) for c in range(K2)]
    flat_sp=[x for r in sp for x in r]
    vsp,_=var(flat_sp)
    print('projected secret psi(s): dim=%d, var=%.2f sigma=%.2f (model x N/d -> %.2f)'
          %(len(flat_sp), vsp, vsp**.5, (N//dd)*eta/2.0))
    print('projected MLWE instance: secret dim (K1+K2)*d = %d, equations K1*d = %d'
          %((K1+K2)*dd, K1*dd))
    print('NOTE: only A1,A2,b1 used; unstructured A4/B2/E2 block never referenced.')

if __name__=='__main__':
    main()
