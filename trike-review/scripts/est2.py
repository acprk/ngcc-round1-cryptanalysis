
from math import log2
from cryptographic_estimators.SDEstimator import SDEstimator
from cryptographic_estimators.SDEstimator import SDAlgorithms as A
excl=[A.BJMMdw,A.BJMMpdw,A.BJMMplus,A.BothMay,A.MayOzerov,A.BallCollision]
INST={'TRIKE-2':(15581,35,263,128),'TRIKE-5':(35363,55,429,256),'TRIKE-7':(69691,83,659,384),'TRIKE-9':(114043,111,877,512)}
SPEC_KEY={'TRIKE-2':(208.44,185.71,186.02,171.78),'TRIKE-5':(306.97,281.72,281.90,266.61),
          'TRIKE-7':(442.98,415.44,414.98,398.81),'TRIKE-9':(578.22,549.05,548.21,531.41)}
SPEC_MSG={'TRIKE-2':(196.93,175.29,175.16,167.86),'TRIKE-5':(297.54,273.11,272.63,264.86),
          'TRIKE-7':(435.03,408.17,406.97,398.77),'TRIKE-9':(564.68,536.19,534.67,526.21)}
def sd(n,k,w):
    E=SDEstimator(n,k,w,bit_complexities=True,excluded_algorithms=excl)
    return {a:v["estimate"]["time"] for a,v in E.estimate().items()}
for k,(r,d,t,lam) in INST.items():
    n=3*r
    kr=sd(n,2*r,3*d)
    km=sd(n,r,t)
    sp,ss,sb,sc=SPEC_KEY[k]; mp,ms,mb,mc=SPEC_MSG[k]
    print(f"{k} KEY [{n},{2*r},{3*d}]: Prange {kr['Prange']:.2f} (spec {sp}) Stern {kr['Stern']:.2f} (spec {ss}) BJMM {kr['BJMM']:.2f} (spec {sb}) | best-log2r={min(kr.values())-log2(r):.2f} (spec {sc})",flush=True)
    print(f"{k} MSG [{n},{r},{t}]: Prange {km['Prange']:.2f} (spec {mp}) Stern {km['Stern']:.2f} (spec {ms}) BJMM {km['BJMM']:.2f} (spec {mb}) | best-0.5log2r={min(km.values())-0.5*log2(r):.2f} (spec {mc}) claimed {lam}",flush=True)
