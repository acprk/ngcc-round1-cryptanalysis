import sys, time, subprocess, statistics, dr0, e2_common as C
GS=[int(x) for x in sys.argv[1].split(',')]
CAP=100
cnfs=[]
for inst in C.INSTS:
    cnf,xv=dr0.build_fixedpoint_cnf(inst['rk0'],inst['rk1'])
    cnfs.append((cnf,xv,inst['x']))
ordr=C.order('c')
tag=sys.argv[2]
def solve(cnf,xv,xhex,idxs,wrong):
    a=[]
    for i in idxs:
        b=C.xbit(xhex,i) ^ (1 if wrong else 0)
        a.append(xv[i] if b==1 else -xv[i])
    p='ef_%s.cnf'%tag; cnf.write(p,assumptions=a)
    t=time.time()
    r=subprocess.run(['cryptominisat5','--verb','0','--maxtime',str(CAP),p],capture_output=True,text=True)
    dt=time.time()-t; o=r.stdout
    st='SAT' if 's SATISFIABLE' in o else ('UNSAT' if 's UNSATISFIABLE' in o else 'TO')
    return st,dt
for g in GS:
    idxs=ordr[:g]
    cor=[]; wr=[]
    for cnf,xv,xhex in cnfs:
        cor.append(solve(cnf,xv,xhex,idxs,False))
    for cnf,xv,xhex in cnfs:
        wr.append(solve(cnf,xv,xhex,idxs,True))
    cm=statistics.median([d for _,d in cor]); wm=statistics.median([d for _,d in wr])
    print("g=%3d CORRECT med=%.2fs [%s] | WRONG med=%.2fs [%s]"%(
        g,cm,','.join('%s:%.1f'%(s,d) for s,d in cor),wm,','.join('%s:%.1f'%(s,d) for s,d in wr)),flush=True)
