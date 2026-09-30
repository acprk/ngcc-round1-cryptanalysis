import dr0, random, json, os
random.seed(202609)
INSTS=[]
for t in range(3):
    x=bytes(random.randint(0,255) for _ in range(32))
    k0=bytes(random.randint(0,255) for _ in range(32))
    rk0,rk1,k1=dr0.plant(x,k0)
    assert dr0.DR0(x,rk0,rk1)==x
    INSTS.append({'x':x.hex(),'rk0':rk0,'rk1':rk1})
def xbit(xhex,i):
    xb=bytes.fromhex(xhex); return (xb[i//8]>>(7-(i%8)))&1
def order(struct):
    X0=list(range(0,128)); X1=list(range(128,256))
    if struct=='a': return X0+X1                 # X0 branch first
    if struct=='b': return X1+X0                 # X1 branch first
    if struct=='c':                              # nibble-spread: alternate X0/X1 nibbles
        o=[]
        for n in range(32):                      # 32 nibbles per branch
            o+= list(range(4*n,4*n+4))           # X0 nibble n
            o+= list(range(128+4*n,128+4*n+4))   # X1 nibble n
        return o
    if struct=='d':
        o=list(range(256)); random.Random(7).shuffle(o); return o
