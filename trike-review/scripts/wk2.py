from math import lgamma, log2
L2=log2(2.718281828459045)  # unused
def lc(n,k):  # log2 C(n,k)
    if k<0 or k>n: return float('-inf')
    return (lgamma(n+1)-lgamma(k+1)-lgamma(n-k+1))/0.6931471805599453
def tI(r,d,f):  return log2(3*r*(r-1)/2)+lc(r-f,d-f)-lc(r,d)
def tII(r,d,m): return log2(3*r*(r-1)/(2*(d-m)))+lc(d-1,d-m-1)+lc(r-d-1,d-m-1)-lc(r,d)
def tIII(r,d,m):return log2(3*r)+lc(d,m)+lc(r-d,d-m)-lc(r,d)
INST={'TRIKE-1':(10301,27,201,128),'TRIKE-2':(15581,35,263,128),'TRIKE-3':(22003,41,319,192),
      'TRIKE-5':(35363,55,429,256),'TRIKE-7':(69691,83,659,384),'TRIKE-9':(114043,111,877,512)}
spec={'TRIKE-1':(6,-25.07,7,-28.06,8,-34.31),'TRIKE-2':(7,-34.07,8,-33.07,10,-47.12),
      'TRIKE-3':(8,-44.16,9,-40.00,11,-54.36),'TRIKE-5':(9,-54.15,12,-59.87,14,-74.60),
      'TRIKE-7':(12,-85.00,17,-93.91,21,-93.91),'TRIKE-9':(14,-65.49,22,-130.02,28,-130.02)}
# experimental DFR upper bound on boundary keys (95% CL, 0 failures)
expb={'TRIKE-1':-21.67,'TRIKE-2':-21.67,'TRIKE-3':-21.67,'TRIKE-5':-21.67,'TRIKE-7':-18.35,'TRIKE-9':-18.35}
print("inst      type  m0  specDens  myDens   | bnd  bndDens  +expDFR   claimedDFR  shortfall")
for k,(r,d,t,lam) in INST.items():
    f0,dI,m2,dII,m3,dIII=spec[k]
    for nm,fn,par,sd in (('I',tI,f0,dI),('II',tII,m2,dII),('III',tIII,m3,dIII)):
        v=fn(r,d,par); vb=fn(r,d,par-1); tot=vb+expb[k]
        flag='  <-- SPEC MISMATCH' if abs(v-sd)>0.05 else ''
        print(f"{k:9} {nm:4} {par:3d} {sd:9.2f} {v:8.2f}  | {par-1:3d} {vb:8.2f} {tot:8.2f}  {-lam:8d}  {tot+lam:8.1f}{flag}")
print()
print("required DFR of boundary keys to reach the claimed DFR (bits), vs measurable bound:")
for k,(r,d,t,lam) in INST.items():
    f0,dI,m2,dII,m3,dIII=spec[k]
    worst=max(tI(r,d,f0-1),tII(r,d,m2-1),tIII(r,d,m3-1))
    print(f"  {k:9} worst boundary density 2^{worst:7.2f} -> need DFR <= 2^{-lam-worst:8.2f}; measured bound 2^{expb[k]:.2f} (gap {-lam-worst-expb[k]:.0f} bits)")
