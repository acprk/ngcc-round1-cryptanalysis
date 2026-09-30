# Minimum RegSD attack cost per SYDO level, with CCJ excluded (it overflows at the 512 level).
from cryptographic_estimators.RegSDEstimator import RegSDEstimator
import math
P={'SYDO-160':(16461,16461-480,59),'SYDO-256':(26226,26226-768,94),'SYDO-512':(49941,49941-1456,179)}
for name,(n,k,w) in P.items():
    E=RegSDEstimator(n,k,w,excluded_algorithms=[])
    best=None; rows={}
    for a in E.algorithms():
        if a.__class__.__name__.startswith('CCJ') and n>40000:
            rows[a.__class__.__name__]='skipped (overflow)'; continue
        try:
            t=a.time_complexity(); m=a.memory_complexity()
            rows[a.__class__.__name__]=(round(t,1),round(m,1))
            if best is None or t<best[1]: best=(a.__class__.__name__,t)
        except Exception as e:
            rows[a.__class__.__name__]=f'error: {type(e).__name__}'
    print(f'{name}: n={n} k={k} w={w} n/w={n//w}  log2C(n,w)={math.lgamma(n+1)/math.log(2)-math.lgamma(w+1)/math.log(2)-math.lgamma(n-w+1)/math.log(2):.1f}  log2(n/w)^w={w*math.log2(n//w):.1f}')
    for kk,vv in rows.items(): print(f'    {kk:<16} {vv}')
    print(f'    => MIN {best[0]} = {best[1]:.1f} bits')
