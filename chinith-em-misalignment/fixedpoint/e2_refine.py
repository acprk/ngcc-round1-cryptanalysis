import sys, time, subprocess, statistics, math, dr0, e2_common as C
CAP=400
GS=[int(x) for x in sys.argv[1].split(',')]
tag=sys.argv[2]
Tref=1.86/20e6
ordr=C.order('c')
inst=C.INSTS[0]; cnf,xv=dr0.build_fixedpoint_cnf(inst['rk0'],inst['rk1']); x=inst['x']
def solve(idxs,wrong,seed=0):
    import random as R; rr=R.Random(seed)
    a=[]
    for i in idxs:
        if wrong: b = (rr.randint(0,1) if seed else (C.xbit(x,i)^1))
        else: b=C.xbit(x,i)
        a.append(xv[i] if b==1 else -xv[i])
    p='ref_%s.cnf'%tag; cnf.write(p,assumptions=a)
    t=time.time()
    r=subprocess.run(['cryptominisat5','--verb','0','--maxtime',str(CAP),p],capture_output=True,text=True)
    dt=time.time()-t; o=r.stdout
    st='SAT' if 's SATISFIABLE' in o else ('UNSAT' if 's UNSATISFIABLE' in o else 'TO')
    return st,dt
for g in GS:
    idxs=ordr[:g]
    sc,dc=solve(idxs,False)
    wrs=[solve(idxs,True,s) for s in (0,1,2)]
    wmed=statistics.median([d for _,d in wrs])
    C_exp = g + math.log2(wmed/Tref) if wmed>0 else g
    print("g=%3d CORRECT %s %.1fs | WRONG med=%.1fs [%s] | C(g)=%.1f"%(
        g, sc, dc, wmed, ','.join('%s:%.1f'%(s,d) for s,d in wrs), C_exp),flush=True)
