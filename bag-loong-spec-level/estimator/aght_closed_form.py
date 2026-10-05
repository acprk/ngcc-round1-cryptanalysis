# AGHT (ISIT'18) cost on the BAG-Loong key instance [2n, n]_{2^m}, merged rank r = t1+t2-g
# (spec Table 1).  Equivalent forms of the guess dimension: t' = floor(m(N-k-1)/N), so
# m - t' = ceil(m(k+1)/N), which is what the exponent below uses.
#
# NOTE: the "quantum" column is a bare Grover-on-the-guess figure, printed for information
# only.  It is NOT part of the comment's claim: a bare Grover-iteration count is not a valid
# argument against the call's quantum targets (cf. ngcc.dev kem-34-1).
import math
for name,m,n,(t1,g,t2),cl,qcl in [('128',47,42,(5,4,5),128,80),('256',67,65,(5,3,6),256,128),
                                   ('384',83,83,(6,3,6),384,192),('512',97,104,(7,4,7),512,256)]:
    r=t1+t2-g; N,k=2*n,n
    e=r*math.ceil((k+1)*m/N)-m
    for w in (2.0,2.807):
        p=w*math.log2(m*(N-k-1))
        print(f"BAG-Loong-{name} (m,N,k,r)=({m},{N},{k},{r}) omega={w}: classical 2^{e+p:.1f} (claim {cl}), quantum 2^{e/2+p:.1f} (claim {qcl})")
