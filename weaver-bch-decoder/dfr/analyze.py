import numpy as np, json, sys, math
def load(files):
    hist={}; per=[]
    for f in files:
        for line in open(f):
            if line.startswith('hist '):
                for tok in line.split()[1:]:
                    k,v=tok.split(':'); hist[int(k)]=hist.get(int(k),0)+int(v)
        per.append(np.loadtxt(f+'.perct'))
    return hist,np.vstack(per)
SETS={'W640':(['logs/w640.txt'],128,5,3,2),'W1024':(['logs/w1024.txt'],256,4,7,7),'W2048':(['logs/w2048a.txt','logs/w2048b.txt'],512,4,9,9)}
out={}
for name,(files,n,k,e1,e2) in SETS.items():
    hist,per=load(files); keys=np.array(sorted(hist)); cnt=np.array([hist[x] for x in keys],float); N=cnt.sum()
    m2=(cnt*keys**2).sum()/N; mean=(cnt*keys).sum()/N
    try: M=json.load(open(f'logs/model_{name}.json'))
    except Exception: M=None
    # regression of per-ct mean e^2 on ||r||^2, ||s||^2
    X=np.c_[per[:,1],per[:,0],np.ones(len(per))]; coef,*_=np.linalg.lstsq(X,per[:,2],rcond=None)
    sig=np.sqrt(per[:,2]); a=math.sqrt(2/math.pi)
    pred_corr=(a*a*sig.var())/(m2-(a*sig.mean())**2)  # approx corr(|e_i|,|e_j|) induced by shared (s,r)
    tails=[]
    for x in np.linspace(0,np.abs(keys).max(),12).astype(int):
        emp=cnt[np.abs(keys)>=x].sum()/N
        mod=None
        if M:
            tk=min(M['e_tail'].keys(),key=lambda t:abs(int(t)-x)); mod=(int(tk),M['e_tail'][tk])
        tails.append((int(x),emp,mod))
    out[name]=dict(ncoef=N,mean=mean,second_moment=m2,sigma=math.sqrt(m2),max_abs=int(np.abs(keys).max()),
                   regress_Ect2_Ecu2_Ecv2=[float(c) for c in coef],pred_stride_abs_corr=float(pred_corr),
                   model_sigma=(M['sigma_e'] if M else None),model_moments=(M['moments'] if M else None),tails=tails)
    print(name,json.dumps(out[name],default=float)[:1500]); print()
json.dump(out,open('logs/analyze.json','w'),indent=1,default=float)
