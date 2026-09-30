import time, subprocess, statistics, random, dr0, e2_common as C
CAP=100
def solvecnf(cnf,assumptions,tag='fx'):
    p='fals_%s.cnf'%tag; cnf.write(p,assumptions=assumptions)
    t=time.time()
    r=subprocess.run(['cryptominisat5','--verb','0','--maxtime',str(CAP),p],capture_output=True,text=True)
    dt=time.time()-t; o=r.stdout
    st='SAT' if 's SATISFIABLE' in o else ('UNSAT' if 's UNSATISFIABLE' in o else 'TO')
    return st,dt
ordr=C.order('c')
rng=random.Random(1234)

# --- real key (from E1); fixed point unknown/possibly none ---
pk1='e7eee7615ef35f30e49b482e15cae75007201e12617b0feda7e1647796ff022b'
out=subprocess.check_output(['./dr0_lib','kbar',pk1]).decode()
r0=[l for l in out.split('\n') if l.startswith('rk0=')][0].split('rk0=')[-1]
r1=[l for l in out.split('\n') if l.startswith('rk1=')][0].split('rk1=')[-1]
rrk0,rrk1=dr0.rk_words(r0),dr0.rk_words(r1)
real_cnf,real_xv=dr0.build_fixedpoint_cnf(rrk0,rrk1)

# --- planted inst0 ---
inst=C.INSTS[0]; pl_cnf,pl_xv=dr0.build_fixedpoint_cnf(inst['rk0'],inst['rk1']); plx=inst['x']

print("## Falsification",flush=True)
for g in [160,128]:
    idxs=ordr[:g]
    # planted: all-flip wrong
    a=[ (pl_xv[i] if (C.xbit(plx,i)^1)==1 else -pl_xv[i]) for i in idxs]
    stf,dtf=solvecnf(pl_cnf,a,'plflip')
    # planted: random wrong (5 trials)
    rw=[]
    for _ in range(5):
        a=[]
        for i in idxs:
            b=rng.randint(0,1)
            a.append(pl_xv[i] if b==1 else -pl_xv[i])
        rw.append(solvecnf(pl_cnf,a,'plrnd'))
    # real: random fix (5 trials) - almost surely UNSAT (no/rare fixed point)
    rr=[]
    for _ in range(5):
        a=[]
        for i in idxs:
            b=rng.randint(0,1)
            a.append(real_xv[i] if b==1 else -real_xv[i])
        rr.append(solvecnf(real_cnf,a,'realrnd'))
    print("g=%3d PLANTED all-flip: %s %.2fs | PLANTED rnd-wrong med=%.2fs [%s] | REAL rnd-fix med=%.2fs [%s]"%(
        g, stf, dtf,
        statistics.median([d for _,d in rw]), ','.join('%s:%.1f'%(s,d) for s,d in rw),
        statistics.median([d for _,d in rr]), ','.join('%s:%.1f'%(s,d) for s,d in rr)),flush=True)
