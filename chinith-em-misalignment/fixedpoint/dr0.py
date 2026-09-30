#!/usr/bin/env python3
"""Bit-exact Python model of uBlock-256/256 DR0 (rounds 0,1) + CNF encoder for
DR0(x)=x.  Validated against the real C library oracle (dr0_lib)."""
import sys, subprocess, os, random

SBOX = [0x7,0x4,0x9,0xc,0xb,0xa,0xd,0x8,0xf,0xe,0x1,0x6,0x0,0x3,0x2,0x5]
INV  = [SBOX.index(i) for i in range(16)]

def rotl32(x,n): n&=31; return ((x<<n)|(x>>(32-n)))&0xffffffff if n else x
def ld(b,off,w): p=off+4*w; return (b[p]<<24)|(b[p+1]<<16)|(b[p+2]<<8)|b[p+3]
def st(v): return bytes([(v>>24)&0xff,(v>>16)&0xff,(v>>8)&0xff,v&0xff])
def B0(w): return (w>>24)&0xff
def B1(w): return (w>>16)&0xff
def B2(w): return (w>>8)&0xff
def B3(w): return w&0xff
def PK(a,b,c,d): return ((a<<24)|(b<<16)|(c<<8)|d)&0xffffffff
def perm_PL(w0,w1,w2,w3):
    return [PK(B2(w0),B3(w1),B0(w2),B1(w3)),
            PK(B3(w0),B2(w1),B1(w2),B0(w3)),
            PK(B1(w0),B0(w1),B3(w3),B2(w2)),
            PK(B2(w3),B3(w2),B1(w1),B0(w0))]
def perm_PR(w0,w1,w2,w3):
    return [PK(B2(w1),B3(w2),B1(w0),B0(w3)),
            PK(B1(w2),B0(w1),B2(w0),B3(w3)),
            PK(B3(w1),B0(w0),B1(w3),B2(w2)),
            PK(B2(w3),B3(w0),B0(w2),B1(w1))]
def sbyte(v): return (SBOX[(v>>4)&0xf]<<4)|SBOX[v&0xf]
def sword(a):
    return ((sbyte((a>>24)&0xff)<<24)|(sbyte((a>>16)&0xff)<<16)|
            (sbyte((a>>8)&0xff)<<8)|sbyte(a&0xff))
def round_fn(X0,X1,rk):
    o0=[0]*4;o1=[0]*4
    for w in range(4):
        a=X0[w]^rk[w]; b=X1[w]^rk[w+4]
        a=sword(a); b=sword(b)
        b^=a; a^=rotl32(b,4); b^=rotl32(a,8); a^=rotl32(b,8); b^=rotl32(a,20); a^=b
        o0[w]=a; o1[w]=b
    X0n=perm_PL(*o0); X1n=perm_PR(*o1)
    return X0n,X1n
def rk_words(rk_hex):
    rb=bytes.fromhex(rk_hex); return [ld(rb,0,w) for w in range(8)]
def DR0(x_bytes, rk0, rk1):
    X0=[ld(x_bytes,0,w) for w in range(4)]; X1=[ld(x_bytes,16,w) for w in range(4)]
    X0,X1=round_fn(X0,X1,rk0); X0,X1=round_fn(X0,X1,rk1)
    return b''.join(st(X0[w]) for w in range(4))+b''.join(st(X1[w]) for w in range(4))

# ---------------- CNF encoder ----------------
# state as 256-bit list, bit i -> byte i//8, MSB first
class CNF:
    def __init__(self): self.n=0; self.clauses=[]; self.xors=[]
    def newv(self): self.n+=1; return self.n
    def newvec(self,k): return [self.newv() for _ in range(k)]
    def clause(self,lits): self.clauses.append(lits)
    def xor(self,vars_,const):
        # XOR of vars == const (const in {0,1}); vars_ may include ('c',) for constant 1
        v=[x for x in vars_ if x!=0]
        # default all-positive parity target=1; one negation flips to 0
        lits=list(v)
        if const==0: lits[0]=-lits[0]
        self.xors.append(lits)
    def write(self,path,assumptions=None):
        with open(path,'w') as f:
            f.write("p cnf %d %d\n"%(self.n,len(self.clauses)+len(self.xors)+(len(assumptions) if assumptions else 0)))
            for c in self.clauses: f.write(' '.join(map(str,c))+' 0\n')
            for x in self.xors: f.write('x '+' '.join(map(str,x))+' 0\n')
            if assumptions:
                for a in assumptions: f.write('%d 0\n'%a)

def sbox_cnf_clauses(cnf, invars, outvars, table):
    # invars,outvars: 4 vars each; table[in4]=out4 ; forbid all wrong (in,out) via clauses:
    # For each input pattern, out must equal table[in]; encode as: for each of 4 out bits,
    # (in==pattern) -> outbit == expected.  Use implication clauses.
    for pin in range(16):
        # literals asserting NOT(in==pin): OR of flipped input lits
        base=[ (-invars[b] if (pin>>(3-b))&1 else invars[b]) for b in range(4) ]
        pout=table[pin]
        for b in range(4):
            ob=(pout>>(3-b))&1
            # in==pin -> outvars[b]==ob : clause = base OR (outvars[b] if ob else -outvars[b])
            cnf.clause(base+[ outvars[b] if ob else -outvars[b] ])

def build_fixedpoint_cnf(rk0, rk1, target=None):
    """Encode DR0(x)=x (target=None) or DR0(x)=target (target=32-byte const, for
    preimage diagnostic). Returns (cnf, xvars) where xvars[0..255] input bits."""
    cnf=CNF()
    x=cnf.newvec(256)  # input state bits, bit i (MSB-first per byte)
    def bit(byteval_list): pass
    # helper: represent state as 256 linear forms. form = (frozenset(vars), const)
    # We'll do explicit: state = list of 256 (set,const)
    def lin_bit(var): return ({var},0)
    def xor_forms(fa,fb):
        s=fa[0]^fb[0]; return (s, fa[1]^fb[1])
    def xor_const(f,c): return (f[0], f[1]^c)
    # round key bits: rk is 8 words 32-bit -> 256 bits MSB-first (word0 hi..). But state layout:
    # X0 = words0..3 (bits 0..127), X1=words4..7 (bits128..255). rk[w] applies to X0[w], rk[w+4] to X1[w].
    def rkbits(rk):
        bits=[0]*256
        for w in range(4):
            for j in range(32): bits[32*w+j]=(rk[w]>>(31-j))&1     # X0 half
            for j in range(32): bits[128+32*w+j]=(rk[w+4]>>(31-j))&1 # X1 half
        return bits
    # state indexing helpers operating on the 8-word view matching C (word bits MSB-first)
    # We keep state as 256 forms indexed 0..255 with same layout as rkbits.
    state=[lin_bit(x[i]) for i in range(256)]
    def apply_round(state, rk, cnf):
        rb=rkbits(rk)
        # addkey
        state=[xor_const(state[i], rb[i]) for i in range(256)]
        # sbox layer: 64 nibbles (bits 4n..4n+3). materialize inputs, fresh outputs.
        outstate=[None]*256
        for n in range(64):
            invars=[]
            for k in range(4):
                f=state[4*n+k]
                iv=cnf.newv()
                # iv == XOR(form) : xor of {iv}|form.vars == form.const
                cnf.xor([iv]+list(f[0]), f[1])
                invars.append(iv)
            outvars=cnf.newvec(4)
            sbox_cnf_clauses(cnf, invars, outvars, SBOX)
            for k in range(4): outstate[4*n+k]=lin_bit(outvars[k])
        state=outstate
        # linear layer: operate per word on forms. Need word-level: X0 words bits, X1 words bits.
        # Reconstruct 8 words each as list of 32 forms.
        def getword(half,w):  # half 0->X0(bits0..127),1->X1(bits128..255)
            base=(0 if half==0 else 128)+32*w
            return [state[base+j] for j in range(32)]
        def setword(newstate,half,w,forms):
            base=(0 if half==0 else 128)+32*w
            for j in range(32): newstate[base+j]=forms[j]
        # per word compute a,b linear mixing where a=X0[w] forms, b=X1[w] forms (32 each)
        newstate=[None]*256
        # helper rotl on 32 forms (list index j = bit (31-j) value; MSB-first). rotl32(x,n):
        # y_bitpos = x_bitpos rotated. bit "position" p in 0..31 where value bit p = (x>>p)&1.
        # our list index j corresponds to bit position (31-j). rotl by n: out bit pos p = in bit pos (p-n).
        def rot(forms,n):
            out=[None]*32
            for j in range(32):
                p=31-j                       # output bit position
                sp=(p-n)%32                  # source bit position
                sj=31-sp
                out[j]=forms[sj]
            return out
        def xlist(fa,fb): return [xor_forms(fa[i],fb[i]) for i in range(32)]
        for w in range(4):
            a=getword(0,w); b=getword(1,w)
            b=xlist(b,a)
            a=xlist(a,rot(b,4))
            b=xlist(b,rot(a,8))
            a=xlist(a,rot(b,8))
            b=xlist(b,rot(a,20))
            a=xlist(a,b)
            setword(newstate,0,w,a); setword(newstate,1,w,b)
        state=newstate
        # permutation PL on X0 (bytes), PR on X1. Work at byte level: byte perms defined on words.
        # We have forms per bit. Build words as 4 bytes; perm maps output byte<-input byte.
        # Express PL/PR as bit permutation over the 128-bit half.
        def half_bits(half):
            base=0 if half==0 else 128
            return [state[base+j] for j in range(128)]
        def byte_of(halfforms,wi,bi):  # word wi (0..3), byte bi(0..3) -> 8 forms
            base=32*wi+8*bi; return halfforms[base:base+8]
        def build_half_from_words(words):  # words: list of 4 words, each list of 4 bytes(8 forms)
            out=[]
            for wi in range(4):
                for bi in range(4): out+=words[wi][bi]
            return out
        hL=half_bits(0); hR=half_bits(1)
        def bytes_of_word(hf,wi): return [byte_of(hf,wi,bi) for bi in range(4)]
        Lw=[bytes_of_word(hL,wi) for wi in range(4)]  # Lw[wi][bi]=8 forms
        Rw=[bytes_of_word(hR,wi) for wi in range(4)]
        # PL: out word0 bytes = B2(w0),B3(w1),B0(w2),B1(w3); etc  (Bk = byte k)
        def Bk(words,wi,k): return words[wi][k]
        PLout=[
            [Bk(Lw,0,2),Bk(Lw,1,3),Bk(Lw,2,0),Bk(Lw,3,1)],
            [Bk(Lw,0,3),Bk(Lw,1,2),Bk(Lw,2,1),Bk(Lw,3,0)],
            [Bk(Lw,0,1),Bk(Lw,1,0),Bk(Lw,3,3),Bk(Lw,2,2)],
            [Bk(Lw,3,2),Bk(Lw,2,3),Bk(Lw,1,1),Bk(Lw,0,0)],
        ]
        PRout=[
            [Bk(Rw,1,2),Bk(Rw,2,3),Bk(Rw,0,1),Bk(Rw,3,0)],
            [Bk(Rw,2,1),Bk(Rw,1,0),Bk(Rw,0,2),Bk(Rw,3,3)],
            [Bk(Rw,1,3),Bk(Rw,0,0),Bk(Rw,3,1),Bk(Rw,2,2)],
            [Bk(Rw,3,2),Bk(Rw,0,3),Bk(Rw,2,0),Bk(Rw,1,1)],
        ]
        newhalfL=build_half_from_words(PLout)
        newhalfR=build_half_from_words(PRout)
        fin=[None]*256
        for j in range(128): fin[j]=newhalfL[j]; fin[128+j]=newhalfR[j]
        return fin
    state=apply_round(state, rk0, cnf)
    state=apply_round(state, rk1, cnf)
    if target is None:
        # fixed point: state[i] (form) == x[i]
        for i in range(256):
            f=state[i]
            cnf.xor([x[i]]+list(f[0]), f[1])
    else:
        # preimage: state[i] (form) == target bit i (MSB-first per byte)
        for i in range(256):
            f=state[i]
            tb=(target[i//8]>>(7-(i%8)))&1
            cnf.xor(list(f[0]), f[1]^tb)
    return cnf, x

if __name__=='__main__':
    cmd=sys.argv[1]
    if cmd=='validate':
        ORACLE=sys.argv[2]; pk1=sys.argv[3]
        out=subprocess.check_output([ORACLE,'kbar',pk1]).decode()
        # parse rk0,rk1
        rk0h=[l for l in out.split('\n') if l.startswith('rk0=')][0].split('rk0=')[-1]
        rk1h=[l for l in out.split('\n') if l.startswith('rk1=')][0].split('rk1=')[-1]
        rk0=rk_words(rk0h); rk1=rk_words(rk1h)
        random.seed(1); fails=0
        for _ in range(2000):
            x=bytes(random.randint(0,255) for _ in range(32))
            py=DR0(x,rk0,rk1)
            c=subprocess.check_output([ORACLE,'dr0',pk1,x.hex()]).decode().strip()
            if py.hex()!=c: fails+=1; print("MISMATCH",x.hex(),py.hex(),c); break
        print("py-vs-C DR0: %d mismatches / 2000"%fails)

# ---------- E2: linear/sbox layer decomposition for PLANTED instances ----------
def _S(state):   # nibble sbox on 32 bytes
    return bytes(sbyte(b) for b in state)
def _Sinv(state):
    return bytes(((INV[(b>>4)&0xf]<<4)|INV[b&0xf]) for b in state)
def _L(state):   # round linear part: mix per word-pair then PL/PR ; input=sbox-output state
    X0=[ld(state,0,w) for w in range(4)]; X1=[ld(state,16,w) for w in range(4)]
    o0=[0]*4; o1=[0]*4
    for w in range(4):
        a=X0[w]; b=X1[w]
        b^=a; a^=rotl32(b,4); b^=rotl32(a,8); a^=rotl32(b,8); b^=rotl32(a,20); a^=b
        o0[w]=a; o1[w]=b
    Xn0=perm_PL(*o0); Xn1=perm_PR(*o1)
    return b''.join(st(Xn0[w]) for w in range(4))+b''.join(st(Xn1[w]) for w in range(4))
def _invperm(fwd,words):
    mp=[]
    for iw in range(4):
        for ib in range(4):
            ww=[0,0,0,0]; ww[iw]=0xff<<(8*(3-ib)); o=fwd(*ww)
            for ow in range(4):
                for ob in range(4):
                    if (o[ow]>>(8*(3-ob)))&0xff==0xff: mp.append((ow,ob,iw,ib))
    x=[0,0,0,0]
    for ow,ob,iw,ib in mp:
        x[iw]|=((words[ow]>>(8*(3-ob)))&0xff)<<(8*(3-ib))
    return x
def _Linv(state):
    X0=[ld(state,0,w) for w in range(4)]; X1=[ld(state,16,w) for w in range(4)]
    a=_invperm(perm_PL,X0); b=_invperm(perm_PR,X1)
    # reverse mix: b^=a;a^=rot(b,4);b^=rot(a,8);a^=rot(b,8);b^=rot(a,20);a^=b
    a=[a[w]^b[w] for w in range(4)]
    b=[b[w]^rotl32(a[w],20) for w in range(4)]
    a=[a[w]^rotl32(b[w],8) for w in range(4)]
    b=[b[w]^rotl32(a[w],8) for w in range(4)]
    a=[a[w]^rotl32(b[w],4) for w in range(4)]
    b=[b[w]^a[w] for w in range(4)]
    return b''.join(st(a[w]) for w in range(4))+b''.join(st(b[w]) for w in range(4))
def plant(x, k0):
    """return (rk0words, rk1words) s.t. DR0_{rk0,rk1}(x)=x by construction."""
    z=_L(_S(bytes(a^b for a,b in zip(x,k0))))
    k1=bytes(a^b for a,b in zip(z, _Sinv(_Linv(x))))
    return rk_words(k0.hex()), rk_words(k1.hex()), k1
