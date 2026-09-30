import numpy as np
D=512; sig=69.76/1.026
def ndft(x):
    i=np.arange(D); k=np.arange(D); return np.exp(1j*np.pi*np.outer(2*k+1,i)/D)@x
H=lambda X: np.conj(np.swapaxes(X,1,2)); I2=np.eye(2)[None]
for kf in ['key0.txt','key7.txt']:
    K=np.loadtxt(kf); f,g,F,G,u,a00,a01,a10,a11=[ndft(K[:,j]) for j in range(9)]
    B=np.zeros((D,2,2),complex); B[:,0,0]=f;B[:,1,0]=g;B[:,0,1]=F;B[:,1,1]=G
    A=np.zeros((D,2,2),complex); A[:,0,0]=a00;A[:,0,1]=a01;A[:,1,0]=a10;A[:,1,1]=a11
    X=sig**2*I2-I2-A@H(A)   # what Â was built for: X should equal B'B'^H
    mu=(np.conj(f)*F+np.conj(g)*G)/(np.abs(f)**2+np.abs(g)**2)   # <b1,b2>/<b1,b1>
    print(kf,'u_hat vs mu: corr(u,mu)=%.4f corr(u,-mu)=%.4f corr(u,conj mu)=%.4f'%tuple(np.real(np.vdot(v,u))/np.linalg.norm(v)/np.linalg.norm(u) for v in [mu,-mu,np.conj(mu)]))
    def U(a): Z=np.zeros((D,2,2),complex); Z[:,0,0]=1;Z[:,1,1]=1;Z[:,0,1]=a; return Z
    cands={'B':B,'B^T':np.swapaxes(B,1,2),'B[1,u]':B@U(u),'B[1,-u]':B@U(-u),'B[1,conj u]':B@U(np.conj(u)),'B[1,-conj u]':B@U(-np.conj(u)),
           'B[1,mu]':B@U(mu),'B[1,-mu]':B@U(-mu),'B^T[1,u]':np.swapaxes(B,1,2)@U(u)}
    for n,Bp in cands.items():
        r=X-Bp@H(Bp); print('   X vs %-14s rms %.3g'%(n,np.sqrt(np.mean(np.abs(r)**2))))
    # also B'^H B' forms
    for n,Bp in [('B[1,u]',B@U(u)),('B[1,-u]',B@U(-u))]:
        r=X-H(Bp)@Bp; print('   X vs (%s)^H(.) rms %.3g'%(n,np.sqrt(np.mean(np.abs(r)**2))))
