#!/usr/bin/env python3
"""Faithful clear-witness evaluation of the SPEC-LITERAL uBlockith-EM EncCstrnts
(p.68) + OWFConstraints (p.68).  Given a DR0 fixed point x and an ARBITRARY pk2,
build w* = in||w||out and check every degree-3 constraint o == 0 in the clear.
QuickSilver soundness: a cleartext-satisfying witness => accepting proof."""
import sys, subprocess, dr0

ORACLE='./dr0_lib'
NB=256  # Nblock
def get_ks(pk1):
    """return list rk[0..24], each = 8 words (32-bit)."""
    out=subprocess.check_output([ORACLE,'kbar_all',pk1]).decode() if False else None
    # build via python key schedule (validated) to get all 25 round keys
    return None

# reuse python key schedule from a tiny reimplementation matching dr0/C
SBOX=dr0.SBOX; INV=dr0.INV
def gf24_mul2(b): return (((b<<1)^0x3)&0xf) if (b&0x8) else ((b<<1)&0xf)
def apply_tk(d): return bytes(((gf24_mul2((x>>4)&0xf)<<4)|gf24_mul2(x&0xf)) for x in d)
def sbyte(v): return (SBOX[(v>>4)&0xf]<<4)|SBOX[v&0xf]
def apply_sn(d): return bytes(sbyte(x) for x in d)
pk=[10,5,15,0,2,7,8,13,1,14,4,12,9,11,3,6,24,25,26,27,28,29,30,31,16,17,18,19,20,21,22,23]
RC=[0x988cc9dd,0xf0e4a1b5,0x21357064,0x8397d2c6,0xc7d39682,0x4f5b1e0a,0x5e4a0f1b,0x7c682d39,
    0x392d687c,0xb3a7e2f6,0xa7b3f6e2,0x8e9adfcb,0xdcc88d99,0x786c293d,0x30246175,0xa1b5f0e4,
    0x8296d3c7,0xc5d19480,0x4a5e1b0f,0x55410410,0x6b7f3a2e,0x17034652,0xeffbbeaa,0x1f0b4e5a]
def apply_nibble_perm(src,perm,tot=32):
    nb=(tot+1)//2; nib=[]
    for i in range(nb): nib+=[(src[i]>>4)&0xf, src[i]&0xf]
    on=[nib[perm[j]] for j in range(tot)]
    return bytes(((on[2*i]<<4)|on[2*i+1]) for i in range(nb))
def set_key(key):
    K0=bytearray(key[0:8]);K1=bytearray(key[8:16]);K2=bytearray(key[16:24]);K3=bytearray(key[24:32])
    def storerk(K0,K1,K2,K3):
        w=[]
        for KK in (K0,K1,K2,K3):
            w.append((KK[0]<<24)|(KK[1]<<16)|(KK[2]<<8)|KK[3])
            w.append((KK[4]<<24)|(KK[5]<<16)|(KK[6]<<8)|KK[7])
        return w
    rk=[storerk(K0,K1,K2,K3)]
    for i in range(1,25):
        tmp=bytearray(K0)+bytearray(K1)
        tmp=bytearray(apply_nibble_perm(tmp,pk,32)); K0=bytearray(tmp[0:8]);K1=bytearray(tmp[8:16])
        t=bytearray(K0); rc=RC[i-1]; t[0]^=(rc>>24)&0xff;t[1]^=(rc>>16)&0xff;t[2]^=(rc>>8)&0xff;t[3]^=rc&0xff
        t=apply_sn(t); K2=bytearray(a^b for a,b in zip(K2,t))
        t=apply_tk(K1); K3=bytearray(a^b for a,b in zip(K3,t))
        nK0,nK1,nK2,nK3=bytearray(K2),bytearray(K3),bytearray(K1),bytearray(K0)
        K0,K1,K2,K3=nK0,nK1,nK2,nK3
        rk.append(storerk(K0,K1,K2,K3))
    return rk  # rk[0..24], each 8 words

def words_to_bytes(ws):  # 8 words -> 32 bytes (X0 words0-3, X1 words4-7)
    b=b''.join(dr0.st(w) for w in ws); return b
def bytes_to_state(b): return [dr0.ld(b,0,w) for w in range(4)],[dr0.ld(b,16,w) for w in range(4)]

def round_no_white(X0,X1,rk):  # one round: addkey,sbox,linear,perm  == dr0.round_fn
    return dr0.round_fn(X0,X1,rk)
def two_round(block, rk_i, rk_i1, final_white=None):
    X0,X1=bytes_to_state(block)
    X0,X1=round_no_white(X0,X1,rk_i)
    X0,X1=round_no_white(X0,X1,rk_i1)
    out=b''.join(dr0.st(X0[w]) for w in range(4))+b''.join(dr0.st(X1[w]) for w in range(4))
    if final_white is not None:
        wk=words_to_bytes(final_white)
        out=bytes(a^b for a,b in zip(out,wk))
    return out

# ---------- faithful spec EncCstrnts o-vector evaluation ----------
def rotl32(x,n): return dr0.rotl32(x,n)
def inv_sword(a):
    return ((( (INV[(dr0.B0(a)>>4)&0xf]<<4)|INV[dr0.B0(a)&0xf])<<24)|
            (( (INV[(dr0.B1(a)>>4)&0xf]<<4)|INV[dr0.B1(a)&0xf])<<16)|
            (( (INV[(dr0.B2(a)>>4)&0xf]<<4)|INV[dr0.B2(a)&0xf])<<8)|
            (  (INV[(dr0.B3(a)>>4)&0xf]<<4)|INV[dr0.B3(a)&0xf]))
def perm_PL_inv(w):
    # invert dr0.perm_PL
    y=[0,0,0,0];
    # forward maps computed; build inverse by brute over byte positions
    # Represent forward as list of (outword,outbytepos)->(inword,inbytepos). Easier: invert via search.
    return _inv_perm(dr0.perm_PL,w)
def perm_PR_inv(w): return _inv_perm(dr0.perm_PR,w)
def _inv_perm(fwd,w):
    # w: 4 words (the permuted value); find pre-image x (4 words) s.t. fwd(x)=w. Perm is a byte permutation.
    # Build byte permutation table once.
    # Determine mapping by feeding unit bytes.
    import functools
    mp=[]  # for each (outword,outbyte) which (inword,inbyte)
    for iw in range(4):
        for ib in range(4):
            words=[0,0,0,0]; words[iw]=0xff<<(8*(3-ib))
            o=fwd(*words)
            for ow in range(4):
                for ob in range(4):
                    if (o[ow]>>(8*(3-ob)))&0xff==0xff:
                        mp.append((ow,ob,iw,ib))
    x=[0,0,0,0]
    for ow,ob,iw,ib in mp:
        byte=(w[ow]>>(8*(3-ob)))&0xff
        x[iw]|=byte<<(8*(3-ib))
    return x

def enc_constraints_ok(w_star_blocks, rk, R=24, verbose=False):
    """w_star_blocks: list of 14 blocks (bytes32). rk: rk[0..24]. Returns True if all o==0."""
    allzero=True; nz=0
    for i in range(0,R-1,2):
        j=i//2
        block_j=w_star_blocks[j]
        X0,X1=bytes_to_state(block_j)
        # round i (steps 11-20)
        X0,X1=round_no_white(X0,X1,rk[i])
        # steps 21-23: y = state + k[i+1]
        ki1=rk[i+1]
        y0=[X0[w]^ki1[w] for w in range(4)]
        y1=[X1[w]^ki1[w+4] for w in range(4)]
        # target block
        if i==R-2:
            tgt=w_star_blocks[j+1]
            ki2=rk[i+2]
            T0,T1=bytes_to_state(tgt)
            T0=[T0[w]^ki2[w] for w in range(4)]
            T1=[T1[w]^ki2[w+4] for w in range(4)]
        else:
            tgt=w_star_blocks[j+1]
            T0,T1=bytes_to_state(tgt)
        # steps 31-38 inverse perm + inverse linear
        T1=perm_PR_inv(T1); T0=perm_PL_inv(T0)
        # inverse of: b^=a;a^=rot(b,4);b^=rot(a,8);a^=rot(b,8);b^=rot(a,20);a^=b  (a=x0,b=x1)
        a=T0; b=T1
        # reverse order
        a=[a[w]^b[w] for w in range(4)]                      # undo a^=b
        b=[b[w]^rotl32(a[w],20) for w in range(4)]           # undo b^=rot(a,20)
        a=[a[w]^rotl32(b[w],8) for w in range(4)]            # undo a^=rot(b,8)
        b=[b[w]^rotl32(a[w],8) for w in range(4)]            # undo b^=rot(a,8)
        a=[a[w]^rotl32(b[w],4) for w in range(4)]            # undo a^=rot(b,4)
        b=[b[w]^a[w] for w in range(4)]                      # undo b^=a
        # steps 39-40 InvSubWord
        z0=[inv_sword(a[w]) for w in range(4)]
        z1=[inv_sword(b[w]) for w in range(4)]
        # constraint o = y+z (must be 0)
        for w in range(4):
            if (y0[w]^z0[w])!=0 or (y1[w]^z1[w])!=0:
                allzero=False; nz+=1
        if verbose: print("  j=%2d i=%2d ok=%s"%(j,i, all((y0[w]^z0[w])==0 and (y1[w]^z1[w])==0 for w in range(4))))
    return allzero

def reduction_demo(pk1_hex, x_hex, pk2_hex):
    """x need NOT be a fixed point. Build honest chain, report per-j pass/fail.
    Shows: only j=0 can fail (== DR0(x)!=x); pk2 arbitrary."""
    pk1=bytes.fromhex(pk1_hex); x=bytes.fromhex(x_hex); pk2=bytes.fromhex(pk2_hex)
    rk=set_key(pk1)
    blocks=[None]*14
    blocks[0]=x; blocks[1]=x
    for j in range(1,11):
        blocks[j+1]=two_round(blocks[j], rk[2*j], rk[2*j+1])
    blocks[12]=two_round(blocks[11], rk[22], rk[23], final_white=rk[24])
    blocks[13]=bytes(a^b for a,b in zip(x,pk2))
    # per-j evaluation
    fails=[]
    R=24
    for i in range(0,R-1,2):
        j=i//2
        X0,X1=bytes_to_state(blocks[j]); X0,X1=round_no_white(X0,X1,rk[i])
        ki1=rk[i+1]
        y0=[X0[w]^ki1[w] for w in range(4)]; y1=[X1[w]^ki1[w+4] for w in range(4)]
        if i==R-2:
            T0,T1=bytes_to_state(blocks[j+1]); ki2=rk[i+2]
            T0=[T0[w]^ki2[w] for w in range(4)]; T1=[T1[w]^ki2[w+4] for w in range(4)]
        else:
            T0,T1=bytes_to_state(blocks[j+1])
        T1=perm_PR_inv(T1); T0=perm_PL_inv(T0)
        a=T0;b=T1
        a=[a[w]^b[w] for w in range(4)]; b=[b[w]^rotl32(a[w],20) for w in range(4)]
        a=[a[w]^rotl32(b[w],8) for w in range(4)]; b=[b[w]^rotl32(a[w],8) for w in range(4)]
        a=[a[w]^rotl32(b[w],4) for w in range(4)]; b=[b[w]^a[w] for w in range(4)]
        z0=[inv_sword(a[w]) for w in range(4)]; z1=[inv_sword(b[w]) for w in range(4)]
        ok=all((y0[w]^z0[w])==0 and (y1[w]^z1[w])==0 for w in range(4))
        if not ok: fails.append(j)
    dr0out=two_round(x, rk[0], rk[1])
    print("pk1=%s"%pk1_hex)
    print("x  =%s (random, NOT a fixed point)"%x_hex)
    print("pk2=%s (arbitrary)"%pk2_hex)
    print("failing constraint indices j:", fails)
    print("DR0(x)==x ?", dr0out==x, " (j=0 constraint)")
    print("=> Only j=0 fails; it is exactly DR0(x)=x. All j=1..11 pass for ARBITRARY pk2.")
    return fails

def build_and_check(pk1_hex, x_hex, pk2_hex):
    pk1=bytes.fromhex(pk1_hex); x=bytes.fromhex(x_hex); pk2=bytes.fromhex(pk2_hex)
    rk=set_key(pk1)
    # sanity: DR0(x)=x?
    b0=two_round(x, rk[0], rk[1])
    assert b0==x, "x is NOT a DR0 fixed point!"
    # build witness w = [S0..S22] = block_1..block_12 (12 blocks)
    blocks=[None]*14
    blocks[0]=x           # w*[0]=in
    blocks[1]=x           # w*[1]=w[0]=S0=in
    for j in range(1,11):
        blocks[j+1]=two_round(blocks[j], rk[2*j], rk[2*j+1])
    # last: j=11 => block_12 with final whitening k[24]
    blocks[12]=two_round(blocks[11], rk[22], rk[23], final_white=rk[24])
    # out = block_13 = in ^ pk2 (ARBITRARY pk2; never read by spec loop)
    blocks[13]=bytes(a^b for a,b in zip(x,pk2))
    ok=enc_constraints_ok(blocks, rk, verbose=True)
    # keyspace reduction: w[0]*w[1]=0 -> first two bits of in
    bit0=(x[0]>>7)&1; bit1=(x[0]>>6)&1
    ks_ok=(bit0*bit1==0)
    print("EncCstrnts all-zero: %s"%ok)
    print("keyspace-reduction w[0]*w[1]=0: bit0=%d bit1=%d -> %s"%(bit0,bit1,'OK' if ks_ok else 'VIOLATED'))
    print("pk2 used (arbitrary): %s"%pk2_hex)
    print("=> spec-literal EM verifier ACCEPTS: %s"%(ok and ks_ok))
    return ok and ks_ok

if __name__=='__main__':
    # usage:  spec_witness.py demo  <pk1hex> <xhex> <pk2hex>   random x: shows only j=0 fails (= DR0(x)!=x)
    #         spec_witness.py check <pk1hex> <xhex> <pk2hex>   x must be a DR0 fixed point: spec-literal verifier accepts
    if len(sys.argv)==5 and sys.argv[1] in ('demo','check'):
        (reduction_demo if sys.argv[1]=='demo' else build_and_check)(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print(__doc__ or ''); print("usage: spec_witness.py demo|check <pk1hex> <xhex> <pk2hex>"); sys.exit(1)
