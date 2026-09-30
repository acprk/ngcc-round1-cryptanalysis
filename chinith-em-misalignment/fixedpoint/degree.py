import dr0, subprocess, random, itertools
pk1='e7eee7615ef35f30e49b482e15cae75007201e12617b0feda7e1647796ff022b'
out=subprocess.check_output(['./dr0_lib','kbar',pk1]).decode()
r0=[l for l in out.split('\n') if l.startswith('rk0=')][0].split('rk0=')[-1]
r1=[l for l in out.split('\n') if l.startswith('rk1=')][0].split('rk1=')[-1]
rk0,rk1=dr0.rk_words(r0),dr0.rk_words(r1)
def f_bit(xbytes):
    y=dr0.DR0(xbytes,rk0,rk1)
    # return 256-bit integer of (y xor x)
    v=0
    for i in range(32):
        b=y[i]^xbytes[i]
        v|=b<<(8*i)
    return v
random.seed(42)
K=16  # subspace dimension
maxdeg_overall=0
for trial in range(4):
    poss=random.sample(range(256),K)
    base=bytearray(random.randint(0,255) for _ in range(32))
    # ensure base has 0 at chosen positions
    for p in poss: base[p//8]&=~(1<<(p%8))
    # tabulate f over the 2^K cube
    T=[0]*(1<<K)
    for mask in range(1<<K):
        xb=bytearray(base)
        for bit in range(K):
            if (mask>>bit)&1:
                p=poss[bit]; xb[p//8]|=(1<<(p%8))
        T[mask]=f_bit(bytes(xb))
    # Mobius transform per output coordinate (do 256 coords together bitwise via XOR)
    A=T[:]
    for i in range(K):
        step=1<<i
        for j in range(1<<K):
            if j&step:
                A[j]^=A[j^step]
    # A[mask] = ANF coefficient (256-bit) for monomial = product of vars in mask
    # degree of coord c = max popcount(mask) with bit c set in A[mask]
    degs=[0]*256
    for mask in range(1<<K):
        pc=bin(mask).count('1')
        a=A[mask]
        if a:
            m=a
            while m:
                c=(m & -m).bit_length()-1
                if pc>degs[c]: degs[c]=pc
                m&=m-1
    md=max(degs)
    maxdeg_overall=max(maxdeg_overall,md)
    print("trial %d: subspace-dim=%d  max coord degree=%d  (mean=%.1f)"%(trial,K,md,sum(degs)/256))
print("OVERALL max restricted degree (lower bound on true deg):",maxdeg_overall)
