#!/usr/bin/env python3
# Intersect several structurally-different recoveries. base = majority vote per coord;
# U' = coords not UNANIMOUS across families. Report |U'| and (scoring) agree-but-wrong.
import sys, glob
files=sys.argv[1:]
G=[[int(x) for x in open(f).read().split()] for f in files]
n=len(G[0]); F=len(G)
strue=None
try: strue=[int(x) for x in open("/tmp/strue.txt").read().split()]
except: pass
base=[0]*n; U=[]
for i in range(n):
    vals=[G[f][i] for f in range(F)]
    from collections import Counter
    c=Counter(vals); mv,mc=c.most_common(1)[0]
    base[i]=mv
    if mc<F: U.append(i)          # not unanimous
print("families=%d  |U'| (non-unanimous) = %d"%(F,len(U)))
if strue:
    bc=sum(1 for i in range(n) if base[i]==strue[i])
    unanimous_wrong=sum(1 for i in range(n) if i not in set(U) and base[i]!=strue[i])
    inU_wrong=sum(1 for i in U if base[i]!=strue[i])
    print("majority-base correct=%d/%d ; UNANIMOUS-BUT-WRONG (missed by U')=%d ; wrong-in-U'=%d"
          %(bc,n,unanimous_wrong,inU_wrong))
with open("/tmp/sh_U.txt","w") as f:
    f.write("%d\n"%len(U)); f.write(" ".join(str(x) for x in base)+"\n"); f.write(" ".join(str(x) for x in U)+"\n")
print("wrote /tmp/sh_U.txt")
