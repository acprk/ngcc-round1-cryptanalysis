import subprocess,time,sys,random,dr0
ORACLE='./dr0_lib'
def get_rks(pk1):
    out=subprocess.check_output([ORACLE,'kbar',pk1]).decode()
    r0=[l for l in out.split('\n') if l.startswith('rk0=')][0].split('rk0=')[-1]
    r1=[l for l in out.split('\n') if l.startswith('rk1=')][0].split('rk1=')[-1]
    return dr0.rk_words(r0),dr0.rk_words(r1)
def run(pk1,tag,maxt):
    rk0,rk1=get_rks(pk1); cnf,xv=dr0.build_fixedpoint_cnf(rk0,rk1)
    p='fp_%s.cnf'%tag; cnf.write(p)
    t0=time.time()
    r=subprocess.run(['cryptominisat5','--verb','0','--maxtime',str(maxt),p],capture_output=True,text=True)
    dt=time.time()-t0
    out=r.stdout
    sat='s SATISFIABLE' in out
    unsat='s UNSATISFIABLE' in out
    st='SAT' if sat else ('UNSAT' if unsat else 'INDET/timeout')
    line="%s pk1=%s : %s (%.2fs)"%(tag,pk1[:16]+'..',st,dt)
    xhex=None
    if sat:
        assign={}
        for l in out.split('\n'):
            if l.startswith('v '):
                for t in l[2:].split():
                    v=int(t)
                    if v: assign[abs(v)]=1 if v>0 else 0
        xb=bytearray(32)
        for i in range(256):
            if assign.get(xv[i],0): xb[i//8]|=(1<<(7-(i%8)))
        xhex=bytes(xb).hex()
        chk=subprocess.check_output([ORACLE,'fp',pk1,xhex]).decode()
        line+="  x=%s VERIFIED=%s"%(xhex,'YES' if 'fixed_point=YES' in chk else 'NO!!')
    print(line,flush=True)
    return st,dt,xhex
if __name__=='__main__':
    maxt=int(sys.argv[1])
    random.seed(2026)
    keys=[('a54dca182530bb1d6d132cded6237b2ed91e3f721fcb1971174494d6493c9d5c','rand7')]
    for i in range(9):
        keys.append((''.join('%02x'%random.randint(0,255) for _ in range(32)),'s%d'%i))
    nsat=0;ntot=0
    for pk,tag in keys:
        st,dt,x=run(pk,tag,maxt); ntot+=1; nsat+= (st=='SAT')
    print("SUMMARY: %d/%d SAT"%(nsat,ntot),flush=True)
