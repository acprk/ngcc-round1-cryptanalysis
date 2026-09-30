import sys,random,dr0,subprocess,json
ORACLE='./dr0_lib'
def get_rks(pk1):
    out=subprocess.check_output([ORACLE,'kbar',pk1]).decode()
    r0=[l for l in out.split('\n') if l.startswith('rk0=')][0].split('rk0=')[-1]
    r1=[l for l in out.split('\n') if l.startswith('rk1=')][0].split('rk1=')[-1]
    return dr0.rk_words(r0),dr0.rk_words(r1)
seed=int(sys.argv[1]); random.seed(seed)
pk1=''.join('%02x'%random.randint(0,255) for _ in range(32))
rk0,rk1=get_rks(pk1); cnf,xv=dr0.build_fixedpoint_cnf(rk0,rk1)
cnf.write('key%d.cnf'%seed)
json.dump({'pk1':pk1,'xv':xv},open('key%d.json'%seed,'w'))
print('key%d pk1=%s vars=%d'%(seed,pk1,cnf.n))
