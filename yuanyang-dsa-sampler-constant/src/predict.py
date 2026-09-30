import numpy as np, sys
D=512; eta=1.026; eta2=eta*eta; sig_sig=69.76; sig=sig_sig/eta
def nd(x): # x_hat[k]=sum x_i zeta^{i(2k+1)}
    z=np.exp(1j*np.pi*np.arange(D)/D); return np.fft.fft(x*z)*1  # fft uses e^{-2pi i}: fix below
def ndft(x):
    i=np.arange(D); k=np.arange(D)
    W=np.exp(1j*np.pi*np.outer(2*k+1,i)/D); return W@x
for kf,mf in [('key0.txt','M_fix_k0.txt'),('key7.txt','M_fix_k7.txt')]:
    K=np.loadtxt(kf); M=np.loadtxt(mf)
    f,g,F,G,u,a00,a01,a10,a11=[ndft(K[:,j]) for j in range(9)]
    # check dump matches gapstat's FFT of f
    assert np.allclose(f, M[:,5]+1j*M[:,6], atol=1e-6), 'fft mismatch'
    Mm=np.zeros((D,2,2),complex); Mm[:,0,0]=M[:,1]/D; Mm[:,1,1]=M[:,2]/D; Mm[:,0,1]=(M[:,3]+1j*M[:,4])/D; Mm[:,1,0]=np.conj(Mm[:,0,1])
    B=np.zeros((D,2,2),complex); B[:,0,0]=f;B[:,1,0]=g;B[:,0,1]=F;B[:,1,1]=G
    A=np.zeros((D,2,2),complex); A[:,0,0]=a00;A[:,0,1]=a01;A[:,1,0]=a10;A[:,1,1]=a11
    H=lambda X: np.conj(np.swapaxes(X,1,2))
    I2=np.eye(2)[None]
    def show(name,P):
        r=Mm-P; print('%s %-38s resid rms %.1f   pred diag means %.1f %.1f'%(kf,name,np.sqrt(np.mean(np.abs(r)**2)),P[:,0,0].real.mean(),P[:,1,1].real.mean()))
    show('isotropic sigma_sig^2 I', sig_sig**2*I2+0*Mm)
    for us,uname in [(1,'+u'),(-1,'-u')]:
        Uc=np.zeros((D,2,2),complex); Uc[:,0,0]=1;Uc[:,1,1]=1;Uc[:,0,1]=us*u
        Bh=B@Uc; BB=Bh@H(Bh)
        show('eta2(AA^H+I+BhBh^H) Bh=B[1,%su]'%uname, eta2*(A@H(A)+I2+BB))
        show('eta2(A^HA+I+BhBh^H) Bh=B[1,%su]'%uname, eta2*(H(A)@A+I2+BB))
        # self-consistency of precomp: A A^H + I + BB vs sigma^2
        Sp=A@H(A)+I2+BB; print('     precomp consistency |AA^H+I+BhBh^H - sigma^2 I| rms %.4g (sigma^2=%.1f)'%(np.sqrt(np.mean(np.abs(Sp-sig**2*I2)**2)),sig**2))
    print('   noise floor ~ %.0f'%(sig_sig**2/np.sqrt(40000)))
