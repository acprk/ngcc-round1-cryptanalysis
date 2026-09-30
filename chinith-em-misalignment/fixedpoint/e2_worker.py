import sys, time, subprocess, statistics, dr0, e2_common as C
struct=sys.argv[1]
GS=[256,224,192,160,144,128,112,96,64,32,0]
CAP=120
# precompute CNFs per instance
cnfs=[]
for inst in C.INSTS:
    cnf,xv=dr0.build_fixedpoint_cnf(inst['rk0'],inst['rk1'])
    cnfs.append((cnf,xv,inst['x']))
ordr=C.order(struct)
def solve(cnf,xv,xhex,idxs,wrong=False):
    assumptions=[]
    for i in idxs:
        b=C.xbit(xhex,i)
        if wrong: b^=1
        assumptions.append(xv[i] if b==1 else -xv[i])
    p='e2_%s.cnf'%struct; cnf.write(p,assumptions=assumptions)
    t=time.time()
    r=subprocess.run(['cryptominisat5','--verb','0','--maxtime',str(CAP),p],capture_output=True,text=True)
    dt=time.time()-t
    o=r.stdout
    st='SAT' if 's SATISFIABLE' in o else ('UNSAT' if 's UNSATISFIABLE' in o else 'TO')
    return st,dt
print("# struct=%s  (correct-guess T(g))"%struct,flush=True)
for g in GS:
    idxs=ordr[:g]
    res=[]
    for cnf,xv,xhex in cnfs:
        st,dt=solve(cnf,xv,xhex,idxs)
        res.append((st,dt))
    med=statistics.median([d for _,d in res])
    sts=','.join(s for s,_ in res)
    print("g=%3d  median=%.2fs  results=[%s] times=%s"%(g,med,sts,['%.1f'%d for _,d in res]),flush=True)
# wrong-guess at a few g on instance 0
print("# struct=%s  (wrong-guess UNSAT time, inst0)"%struct,flush=True)
cnf,xv,xhex=cnfs[0]
for g in [256,192,128,96,64]:
    st,dt=solve(cnf,xv,xhex,ordr[:g],wrong=True)
    print("g=%3d  wrong-> %s  %.2fs"%(g,st,dt),flush=True)
