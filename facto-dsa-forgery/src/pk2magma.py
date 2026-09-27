import sys
# usage: pk2magma.py pk.bin n m out.m   (public key only)
pk=open(sys.argv[1],'rb').read(); n=int(sys.argv[2]); m=int(sys.argv[3]); r=2*n
N3=(r+2)*(r+1)*r//6; assert len(pk)==2*m*N3
fe=[pk[2*i]|(pk[2*i+1]<<8) for i in range(m*N3)]
mons=[(i,j,k) for i in range(r) for j in range(i,r) for k in range(j,r)]
with open(sys.argv[4],'w') as f:
    f.write(f'q:=65519; n:={n}; r:={r}; m:={m};\n')
    f.write('C:=['+',\n'.join('['+','.join(map(str,fe[t*N3:(t+1)*N3]))+']' for t in range(m))+'];\n')
    f.write('Mons:=['+','.join(f'[{i+1},{j+1},{k+1}]' for (i,j,k) in mons)+'];\n')
