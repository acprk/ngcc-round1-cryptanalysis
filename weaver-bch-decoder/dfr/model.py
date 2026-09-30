"""Exact-convolution DFR model of the submitted Weaver reference code.
Per-term distributions are enumerated from the code's own Compress/Decompress formulas and Invq tables.
Unconditional model = spec's model (independence); conditional model = condition on ||s||^2, ||r||^2
via exponential tilting of the CBD (equivalence of ensembles), then integrate over exact norm distributions."""
import numpy as np, re, sys, json, os
from math import comb, log2
from scipy.stats import binom
from scipy.special import logsumexp

SETS = {
 'W640':  dict(q=3329,n=128,k=5,eta1=3,eta2=2,dt=9,du=9,dv=6, hi=(126,112,2), hi_full=127, lo=(26,16,2), lo_full=31, stp=32, table='ref/WeaverKEM-128/invq_table_d9.h', claim=dict(L1=-167.1,L2=-166.3)),
 'W1024': dict(q=7681,n=256,k=4,eta1=7,eta2=7,dt=10,du=10,dv=8, hi=(252,220,4), hi_full=255, lo=(60,36,4), lo_full=63, stp=64, table='ref/WeaverKEM-256/invq_table_d10.h', claim=dict(L1=-233.5,L2=-231.7)),
 'W2048': dict(q=7681,n=512,k=4,eta1=9,eta2=9,dt=11,du=11,dv=9, hi=(511,448,7), hi_full=511, lo=(113,64,7), lo_full=127, stp=128, table='ref/WeaverKEM-512/invq_table_d11.h', claim=dict(L1=-491.2,L2=-488.3)),
}
TINY=1e-310
def comp(x,d,q): return ((((x.astype(np.int64))<<d)+q//2)//q) & ((1<<d)-1)
def decomp(t,d,q): return ((t.astype(np.int64)*q + (1<<(d-1)))>>d)
def centered(x,q):
    x=np.mod(x,q); return np.where(x>q//2,x-q,x)
def cbd(eta):
    v=np.arange(-eta,eta+1); p=np.array([comb(2*eta,eta+i) for i in v],float)/4**eta; return v,p
def dist_from_samples(vals,weights,L):  # array indexed -L..L
    a=np.zeros(2*L+1); np.add.at(a,vals+L,weights); return a
def load_table(path):
    # REF = vendor Reference_Implementation dir (contains WeaverKEM-128/256/512)
    path=os.path.join(os.environ.get('REF','ref'), path[len('ref/'):] if path.startswith('ref/') else path)
    s=open(path).read()
    lo=[int(x) for x in re.search(r'bucket_lo\[\d+\]\s*=\s*\{([^}]*)\}',s).group(1).replace('\n',' ').split(',') if x.strip()]
    sz=[int(x) for x in re.search(r'bucket_size\[\d+\]\s*=\s*\{([^}]*)\}',s).group(1).replace('\n',' ').split(',') if x.strip()]
    return np.array(lo),np.array(sz)
def conv(a,b,L):  # a,b centered arrays; return centered clipped to +-L (mass beyond is folded mod q later -> we keep L=q)
    c=np.convolve(a,b); m=(len(c)-1)//2
    c=c[m-L:m+L+1] if m>=L else np.pad(c,(L-m,L-m)); c[c<TINY]=0; return c
def power(a,e,L):
    res=None; base=a.copy()
    while e:
        if e&1: res=base if res is None else conv(res,base,L)
        e>>=1
        if e: base=conv(base,base,L)
    return res
def fold(a,q,L):  # centered -L..L -> Z_q centered
    out=np.zeros(q); idx=np.mod(np.arange(-L,L+1),q); np.add.at(out,idx,a); return out  # index = residue
def term_dists(P):
    q=P['q']; x=np.arange(q)
    # c_u, c_v : deterministic rounding error of uniform x (code formulas)
    cu=centered(decomp(comp(x,P['du'],q),P['du'],q)-x,q); cv=centered(decomp(comp(x,P['dv'],q),P['dv'],q)-x,q)
    # c_t : Invq lift uniform in table bucket of Compress(t,dt), minus t
    lo,sz=load_table(P['table']); b=comp(x,P['dt'],q)
    ok=np.all((np.mod(x-lo[b],q))<sz[b]); ct_v=[];ct_w=[]
    for bi in range(len(lo)):
        mem=np.mod(lo[bi]+np.arange(sz[bi]),q)
        for t in mem:
            for l in mem: ct_v.append(centered(np.array([l-t]),q)[0]); ct_w.append(1.0/(q*sz[bi]))
    ct_v=np.array(ct_v); ct_w=np.array(ct_w)
    # sanity: every t in exactly one table bucket consistent with compress
    cover=np.zeros(q,int)
    for bi in range(len(lo)): cover[np.mod(lo[bi]+np.arange(sz[bi]),q)]+=1
    return dict(cu=(cu,np.full(q,1/q)),cv=(cv,np.full(q,1/q)),ct=(ct_v,ct_w),table_ok=bool(ok and np.all(cover==1)))
def moments(v,w): v=np.asarray(v,float); return dict(mean=float((v*w).sum()), var=float((v*v*w).sum()-(v*w).sum()**2), m2=float((v*v*w).sum()))
def prod_dist(cvals,cw,rv,rp,L):
    vals=np.add.outer(cvals,np.zeros_like(rv))*0; out=np.zeros(2*L+1)
    for v,p in zip(rv,rp):
        if p==0: continue
        np.add.at(out,(cvals*v)+L,cw*p)
    return out
def tilt(rv,rp,lam):
    w=rp*np.exp(lam*rv**2); return w/w.sum()
def lam_for(rv,rp,target_m2):
    lo,hi=-5.0,5.0
    for _ in range(200):
        mid=(lo+hi)/2; m=(tilt(rv,rp,mid)*rv**2).sum()
        if m<target_m2: lo=mid
        else: hi=mid
    return (lo+hi)/2
def per_bit(edist,q):
    """edist over residues 0..q-1 (index = e mod q). Returns (p_hi, low-layer per-coefficient f-dists)."""
    e=centered(np.arange(q),q); H=(q+1)//2; Q4=q//4
    p_hi=0.0
    for hb in (0,1):
        t=np.mod(hb*H+e,q); bit=(((t<<1)+q//2)//q)&1; p_hi+=0.5*edist[bit!=hb].sum()
    f={}
    for lb in (0,1):
        x=np.mod(lb*Q4+hb*0+e,q)  # high part vanishes mod H in flipabs (hb*H mod H = 0)
        r=np.mod(x,H)-Q4; fa=np.abs(r)
        d=np.zeros(4*H+1); np.add.at(d,fa,edist); f[lb]=d
    p_lo=0.0
    for lb in (0,1):
        s=f[lb]
        for _ in range(3): s=np.convolve(s,f[lb]); s[s<TINY]=0
        idx=np.arange(len(s)); noisy=(idx<H).astype(int)
        p_lo+=0.5*s[noisy!=lb].sum()
    return p_hi,p_lo
def log2sf(t,l,p):
    v=binom.sf(t,l,p)
    if v>0: return log2(v)
    # tiny: leading term
    return log2(comb(l,t+1))+(t+1)*log2(p) if p>0 else -np.inf
def integrate(P,NR,NS,Rp,Sp,LPH,LPL,ph,pl):
    """Integrate conditional per-bit rates over the exact norm distributions: log2 p interpolated
    linearly in (R,S) between grid points (clamped outside), summed over all support points."""
    from scipy.interpolate import RegularGridInterpolator
    def supp(N):
        i=np.nonzero(N>N.max()*1e-90)[0]; return i, N[i]
    Ri,Rw=supp(NR); Si,Sw=supp(NS)
    fh=RegularGridInterpolator((np.array(Rp,float),np.array(Sp,float)),np.array(LPH),bounds_error=False,fill_value=None)
    fl=RegularGridInterpolator((np.array(Rp,float),np.array(Sp,float)),np.array(LPL),bounds_error=False,fill_value=None)
    Rc=np.clip(Ri,Rp[0],Rp[-1]); Sc=np.clip(Si,Sp[0],Sp[-1])
    out={}
    lw=np.add.outer(np.log2(Rw),np.log2(Sw))
    RR,SS=np.meshgrid(Rc,Sc,indexing='ij'); pts=np.c_[RR.ravel(),SS.ravel()]
    lph=fh(pts).reshape(RR.shape); lpl=fl(pts).reshape(RR.shape)
    def lse2(x): x=np.asarray(x).ravel(); m=x.max(); return float(m+np.log2(np.exp2(x-m).sum()))
    out['phi_cond']=lse2(lw+lph); out['plo_cond']=lse2(lw+lpl)
    out['phi_uncond_check']=log2(ph); out['plo_uncond_check']=log2(pl)
    (l1,_,t1)=P['hi']; (l2,_,t2)=P['lo']
    def lsf(lp,t,l):  # leading-term log2 binom.sf for small p: log2 C(l,t+1) + (t+1) log2 p
        return log2(comb(l,t+1))+(t+1)*lp
    out['L1_cond']=lse2(lw+lsf(lph,t1,l1)); out['L2_cond']=lse2(lw+lsf(lpl,t2,l2))
    out['L1_indep_leading']=log2(comb(l1,t1+1))+(t1+1)*log2(ph); out['L2_indep_leading']=log2(comb(l2,t2+1))+(t2+1)*log2(pl)
    out['nobch_hi_payload_cond']=lse2(lw+lph+np.log2(P['hi'][1]))
    return out
def run(name,grid=6):
    P=SETS[name]; q=P['q']; kn=P['k']*P['n']; L=q
    T=term_dists(P); res=dict(set=name,table_ok=T['table_ok'])
    res['moments']={k:moments(*T[k]) for k in ('ct','cu','cv')}
    r1v,r1p=cbd(P['eta1']); r2v,r2p=cbd(P['eta2'])
    # unconditional
    Pt=prod_dist(T['ct'][0],T['ct'][1],r2v,r2p,L); Pu=prod_dist(T['cu'][0],T['cu'][1],r1v,r1p,L)
    cvd=dist_from_samples(T['cv'][0],T['cv'][1],L)
    A=power(Pt,kn,L); B=power(Pu,kn,L); E=conv(conv(A,B,L),cvd,L); ed=fold(E,q,L)
    ph,pl=per_bit(ed,q); ev=centered(np.arange(q),q)
    res['sigma_e']=float(np.sqrt((ed*ev**2).sum()))
    res['p_hi']=ph; res['p_lo']=pl; res['log2_p_hi']=log2(ph); res['log2_p_lo']=log2(pl)
    for tag,(l,k,t),lf in (('L1',P['hi'],P['hi_full']),('L2',P['lo'],P['lo_full'])):
        p=ph if tag=='L1' else pl
        res[tag+'_indep_used']=log2sf(t,l,p); res[tag+'_indep_full']=log2sf(t,lf,p); res[tag+'_claim']=P['claim'][tag]
    res['nobch_hi_payload_log2']=log2(1-(1-ph)**P['hi'][1]) if ph>1e-15 else log2(P['hi'][1]*ph)
    res['e_tail']={int(x):float(ed[np.abs(ev)>=x].sum()) for x in range(0,q//2,max(1,q//64))}
    # conditional on norms
    def norm_dist(v,p):
        sq=np.zeros(v.max()**2+1); np.add.at(sq,v**2,p)
        d=sq.copy(); out=None; e=kn; base=sq
        while e:
            if e&1: out=base if out is None else np.convolve(out,base)
            e>>=1
            if e: base=np.convolve(base,base)
        out[out<TINY]=0; return out
    NR=norm_dist(r2v,r2p); NS=norm_dist(r1v,r1p)
    def grid_of(N):
        c=np.cumsum(N); sf=np.cumsum(N[::-1])[::-1]  # sf[i]=P(X>=i), accurate in the upper tail
        pts=set(int(np.searchsorted(c,x)) for x in np.linspace(0.02,0.98,grid))
        for k in (3.5,8,14,22,32,45):
            i=np.nonzero(sf>=10.0**(-k))[0]
            if len(i): pts.add(int(i[-1]))
        pts=sorted(p for p in pts if p<len(N))
        return pts,None
    Rp,Rw=grid_of(NR); Sp,Sw=grid_of(NS)
    Acache={R:power(prod_dist(T['ct'][0],T['ct'][1],r2v,tilt(r2v,r2p,lam_for(r2v,r2p,R/kn)),L),kn,L) for R in Rp}
    Bcache={S:power(prod_dist(T['cu'][0],T['cu'][1],r1v,tilt(r1v,r1p,lam_for(r1v,r1p,S/kn)),L),kn,L) for S in Sp}
    LPH=np.zeros((len(Rp),len(Sp))); LPL=np.zeros_like(LPH)
    for i,R in enumerate(Rp):
        for j,S in enumerate(Sp):
            ed2=fold(conv(conv(Acache[R],Bcache[S],L),cvd,L),q,L); ph2,pl2=per_bit(ed2,q)
            LPH[i,j]=log2(ph2); LPL[i,j]=log2(pl2)
        print('row',i+1,'/',len(Rp),flush=True)
    res.update(integrate(P,NR,NS,Rp,Sp,LPH,LPL,ph,pl))
    res['grid_R']=Rp; res['grid_S']=Sp; res['LPH']=LPH.tolist(); res['LPL']=LPL.tolist()
    return res
if __name__=='__main__':
    name=sys.argv[1]; r=run(name); json.dump(r,open(f'logs/model_{name}.json','w'),indent=1,default=float)
    for k,v in r.items():
        if k not in ('e_tail','grid_R','grid_S'): print(k,v)
