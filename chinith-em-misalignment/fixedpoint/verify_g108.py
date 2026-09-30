import sys,time,subprocess,statistics,random,dr0,e2_common as C
CAP=400; g=int(sys.argv[1]); which=sys.argv[2]; n=int(sys.argv[3]); seed0=int(sys.argv[4])
ordr=C.order('c'); idxs=ordr[:g]
if which=='real':
    pk1='e7eee7615ef35f30e49b482e15cae75007201e12617b0feda7e1647796ff022b'
    out=subprocess.check_output(['./dr0_lib','kbar',pk1]).decode()
    r0=[l for l in out.split('\n') if l.startswith('rk0=')][0].split('rk0=')[-1]
    r1=[l for l in out.split('\n') if l.startswith('rk1=')][0].split('rk1=')[-1]
    cnf,xv=dr0.build_fixedpoint_cnf(dr0.rk_words(r0),dr0.rk_words(r1))
else:
    inst=C.INSTS[int(which)]; cnf,xv=dr0.build_fixedpoint_cnf(inst['rk0'],inst['rk1'])
ts=[]
for k in range(n):
    rng=random.Random(seed0+k); a=[xv[i] if rng.randint(0,1) else -xv[i] for i in idxs]
    p='vg_%s_%d.cnf'%(which,seed0); cnf.write(p,assumptions=a)
    t=time.time(); r=subprocess.run(['cryptominisat5','--verb','0','--maxtime',str(CAP),p],capture_output=True,text=True); dt=time.time()-t
    st='SAT' if 's SATISFIABLE' in r.stdout else ('UNSAT' if 's UNSATISFIABLE' in r.stdout else 'TO')
    ts.append(dt); print("g=%d %s trial%d %s %.1fs"%(g,which,k,st,dt),flush=True)
print("SUMMARY g=%d %s n=%d mean=%.1f median=%.1f max=%.1f"%(g,which,n,statistics.mean(ts),statistics.median(ts),max(ts)),flush=True)
