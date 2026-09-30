#!/usr/bin/env python3
"""Build CNF for DR0(x)=x, solve with cryptominisat5, verify solution with C oracle."""
import sys, subprocess, time, os
import dr0

ORACLE='./dr0_lib'
def get_rks(pk1):
    out=subprocess.check_output([ORACLE,'kbar',pk1]).decode()
    rk0h=[l for l in out.split('\n') if l.startswith('rk0=')][0].split('rk0=')[-1]
    rk1h=[l for l in out.split('\n') if l.startswith('rk1=')][0].split('rk1=')[-1]
    return dr0.rk_words(rk0h), dr0.rk_words(rk1h)

def solve(pk1, tag):
    rk0,rk1=get_rks(pk1)
    t0=time.time()
    cnf,xv=dr0.build_fixedpoint_cnf(rk0,rk1)
    tb=time.time()-t0
    path='fp_%s.cnf'%tag
    cnf.write(path)
    print("[%s] CNF: %d vars, %d clauses, %d xor-clauses (build %.2fs)"%(tag,cnf.n,len(cnf.clauses),len(cnf.xors),tb))
    t0=time.time()
    res=subprocess.run(['cryptominisat5','--verb','0',path],capture_output=True,text=True)
    ts=time.time()-t0
    lines=res.stdout.split('\n')
    stat=[l for l in lines if l.startswith('s ')]
    print("[%s] cryptominisat: %s  (solve %.3fs)"%(tag,stat[0] if stat else '??',ts))
    if not any('SATISFIABLE' in s and 'UNSAT' not in s for s in stat):
        print("[%s] UNSAT -> no fixed point for this key"%tag); return None,ts
    # parse assignment
    assign={}
    for l in lines:
        if l.startswith('v '):
            for tok in l[2:].split():
                v=int(tok)
                if v!=0: assign[abs(v)]=1 if v>0 else 0
    # reconstruct x bytes: xv[i] is bit i, MSB-first per byte
    xb=bytearray(32)
    for i in range(256):
        b=assign.get(xv[i],0)
        if b: xb[i//8]|=(1<<(7-(i%8)))
    xhex=bytes(xb).hex()
    print("[%s] x = %s"%(tag,xhex))
    # verify with C oracle
    chk=subprocess.check_output([ORACLE,'fp',pk1,xhex]).decode()
    print(chk.strip())
    ok='fixed_point=YES' in chk
    print("[%s] VERIFIED FIXED POINT: %s"%(tag,ok))
    return xhex,ts

if __name__=='__main__':
    pk1=sys.argv[1]; tag=sys.argv[2] if len(sys.argv)>2 else 'k'
    solve(pk1,tag)
