"""End-to-end Monte-Carlo check of the C2 noise model: simulate e''=g*r+f'*m+e' with REAL
negacyclic ring arithmetic in Z[x]/(x^1024+1) and compare the law of <e''_group, y> against
the exact model pmf used by nev_dfr_decoders.py (and against the chi_f<->chi_g swap)."""
import numpy as np, math, itertools
import nev_dfr_decoders as M
K=4; n=1024; q=769; nk=n//K
rng=np.random.default_rng(20260930)

def samp(code,size):
    if code==9: return rng.integers(-1,2,size=size)
    if code==8: return (rng.random(size)<0.125)*1 - (rng.random(size)<0.125)*1  # not exactly T1/8
    eta=code
    return (rng.random((size[0],size[1],eta))<0.5).sum(2)-(rng.random((size[0],size[1],eta))<0.5).sum(2)
def samp8(size):
    u=rng.random(size); return np.where(u<0.125,-1,np.where(u<0.25,1,0))
def negmul(a,b):
    # a,b: (T,n) -> negacyclic product, via FFT-free direct (n small enough with matrix trick)
    T=a.shape[0]; out=np.zeros((T,n))
    F=np.fft.rfft(np.concatenate([a,np.zeros((T,n))],1))*np.fft.rfft(np.concatenate([b,np.zeros((T,n))],1))
    c=np.fft.irfft(F,2*n)
    return np.rint(c[:,:n]-c[:,n:2*n])

def msg(size):
    m=samp(2,size)             # B_2 iid
    # force per-group parity to 1 (M = 1^l): resample coefficient t=3 of each group if needed
    mm=m.reshape(size[0],K,nk) if False else m
    g=np.stack([m[:,j::nk] for j in range(0)],0) if False else None
    return m

BATCH=20000; NBATCH=10   # keep peak RSS ~1 GiB (8 GiB cap)
# groups are {j, j+nk, j+2nk, j+3nk}
idx=[np.arange(nk)+t*nk for t in range(K)]
y=(1,1,1,1)
HLO,HHI=-1200,1200
hist=np.zeros(HHI-HLO+1,dtype=np.int64); nout=0; s1=0.0; s2=0.0; s4=0.0; N=0
for _b in range(NBATCH):
    T=BATCH
    f=samp(1,(T,n)); e=samp(2,(T,n)); g8=samp8((T,n)); r=samp(9,(T,n))
    ee=e.copy()
    # correct conditional law for the 4th group coefficient (spec eq. (5)): resample m_3 from
    # B_2 conditioned on parity = M - (m_0+m_1+m_2) mod 2.  even: {-2:1/8,0:3/4,2:1/8};
    # odd: {-1:1/2,+1:1/2}.  M = 1 (worst-case message).
    need=(1-(ee[:,idx[0]]+ee[:,idx[1]]+ee[:,idx[2]]))%2
    u=rng.random(need.shape)
    odd=np.where(u<0.5,-1,1)
    even=np.where(u<0.125,-2,np.where(u<0.875,0,2))
    ee[:,idx[3]]=np.where(need==1,odd,even)
    assert np.all(sum(ee[:,i] for i in idx)%2==1)
    w=negmul(g8.astype(float),r.astype(float))+negmul(f.astype(float),ee.astype(float))
    cs=np.cumsum(np.stack([ee[:,idx[t]] for t in range(K)],2),axis=2)
    Ep=(2*cs-cs[:,:,-1:]-1)//2
    dvals=np.stack([w[:,idx[t]] for t in range(K)],2)+Ep
    pr=(dvals*np.array(y)).sum(2).ravel().astype(np.int64)
    N+=len(pr); s1+=pr.sum(); s2+=(pr.astype(float)**2).sum(); s4+=(pr.astype(float)**4).sum()
    k2=(pr>=HLO)&(pr<=HHI)
    hist+=np.bincount(pr[k2]-HLO,minlength=HHI-HLO+1)
    nout+=len(pr)-k2.sum()
    del f,e,g8,r,ee,w,cs,Ep,dvals,pr
mean=s1/N; var=s2/N-mean**2
kurt=(s4/N-4*mean*s2/N*1.0+6*mean**2*s2/N/1.0)  # placeholder, recomputed below from hist
xs=np.arange(HLO,HHI+1)
m4=((xs-mean)**4*hist).sum()/N
print("simulated <e''_j,y> for y=(1,1,1,1):  N=%d  mean %.4f  var %.2f  kurt %.4f  (outside hist: %d)"%(
      N,mean,var,m4/var**2,nout))
# exact model pmf for the same y
dg,dr,df=M.dist(8),M.dist(9),M.dist(1)
Bg,pg=M.enum4(dr); aG,lG=M.blockdist(dg,Bg,pg,y,("sg",))
Bep,pep=M.msg_blocks(2,parity=1)
aF,lF=M.blockdist(df,Bep,pep,y,("sf",))
SG,sgl=M.cpow(aG,lG,nk); SFm,sfml=M.cpow(aF,lF,nk-1)
sh=M.eprime_shift(Bep,y,1); a0,l0=M.blockdist(df,Bep,pep,y,("sf0",y),shift=sh)
SF=np.convolve(SFm,a0); sfl=sfml+l0
S=np.convolve(SG,SF); lo=sgl+sfl
x=np.arange(len(S))+lo
mu=(x*S).sum(); var=((x-mu)**2*S).sum(); kur=((x-mu)**4*S).sum()/var**2
print("exact model  (chi_f=B1, chi_g=T1/8):   mean %.4f  var %.2f  kurt %.4f"%(mu,var,kur))
# swapped hypothesis
aG2,lG2=M.blockdist(M.dist(1),Bg,pg,y,("sg2",))
aF2,lF2=M.blockdist(M.dist(8),Bep,pep,y,("sf2",))
SG2,s2l=M.cpow(aG2,lG2,nk); SF2,s3l=M.cpow(aF2,lF2,nk)
S2=np.convolve(SG2,SF2); lo2=s2l+s3l
x2=np.arange(len(S2))+lo2
mu2=(x2*S2).sum(); var2=((x2-mu2)**2*S2).sum()
print("exact model  (chi_f,chi_g SWAPPED):    mean %.4f  var %.2f"%(mu2,var2))
# chi-square of the simulated histogram against the exact pmf over the bulk
cum=np.cumsum(hist)/N
lo_b=int(xs[np.searchsorted(cum,0.005)]); hi_b=int(xs[np.searchsorted(cum,0.995)])
obs=hist[(xs>=lo_b)&(xs<=hi_b)]
exp=S[(x>=lo_b)&(x<=hi_b)]*N
assert len(obs)==len(exp)
sel=exp>=20
chi2=(((obs[sel]-exp[sel])**2)/exp[sel]).sum(); dof=sel.sum()-1
z=(chi2/dof)**(1/3.)  # Wilson-Hilferty
z=((chi2/dof)**(1/3.)-(1-2/(9*dof)))/math.sqrt(2/(9*dof))
print("bulk goodness-of-fit vs exact pmf: chi2=%.1f df=%d Wilson-Hilferty z=%+.2f"%(chi2,dof,z))
