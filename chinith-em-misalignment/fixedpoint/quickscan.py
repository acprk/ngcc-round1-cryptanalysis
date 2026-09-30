import subprocess,time,random,dr0
ORACLE='./dr0_lib'
def get_rks(pk1):
    out=subprocess.check_output([ORACLE,'kbar',pk1]).decode()
    r0=[l for l in out.split('\n') if l.startswith('rk0=')][0].split('rk0=')[-1]
    r1=[l for l in out.split('\n') if l.startswith('rk1=')][0].split('rk1=')[-1]
    return dr0.rk_words(r0),dr0.rk_words(r1)
random.seed(999)
found=[]
for i in range(30):
    pk1=''.join('%02x'%random.randint(0,255) for _ in range(32))
    rk0,rk1=get_rks(pk1); cnf,xv=dr0.build_fixedpoint_cnf(rk0,rk1)
    p='qs.cnf'; cnf.write(p)
    t0=time.time()
    r=subprocess.run(['cryptominisat5','--verb','0','--maxtime','25',p],capture_output=True,text=True)
    dt=time.time()-t0; out=r.stdout
    if 's SATISFIABLE' in out:
        assign={}
        for l in out.split('\n'):
            if l.startswith('v '):
                for t in l[2:].split():
                    v=int(t)
                    if v: assign[abs(v)]=1 if v>0 else 0
        xb=bytearray(32)
        for k in range(256):
            if assign.get(xv[k],0): xb[k//8]|=(1<<(7-(k%8)))
        xhex=bytes(xb).hex()
        chk=subprocess.check_output([ORACLE,'fp',pk1,xhex]).decode()
        ok='fixed_point=YES' in chk
        print("SAT i=%d (%.1fs) pk1=%s x=%s VERIFIED=%s"%(i,dt,pk1,xhex,ok),flush=True)
        found.append((pk1,xhex,ok))
        if len([f for f in found if f[2]])>=3: break
    elif 's UNSATISFIABLE' in out:
        print("UNSAT i=%d (%.1fs) pk1=%s"%(i,dt,pk1[:16]),flush=True)
    else:
        print("timeout i=%d pk1=%s"%(i,pk1[:16]),flush=True)
print("FOUND %d verified fixed points"%len([f for f in found if f[2]]),flush=True)
for pk1,xhex,ok in found:
    if ok: print("KEY",pk1,"X",xhex)
