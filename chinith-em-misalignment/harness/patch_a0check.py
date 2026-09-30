# Instrument sign/verify: record signer's a0_tilde, compare with verifier-reconstructed a0_tilde.
# Equality <=> QuickSilver check that the spec (but not the impl) enforces.
import sys,re
p=sys.argv[1]
s=open(p).read()
hdr='#include <stdio.h>\nunsigned char g_dbg_a0[64]; int g_dbg_a0_ok=-1;\n'
s=hdr+s
# after prover call (first occurrence ending with chall_2);)
i=s.index('_prover(params, a0_tilde'); j=s.index(';',i)+1
s=s[:j]+'\n  memcpy(g_dbg_a0, a0_tilde, params->lambda_bytes);\n'+s[j:]
i=s.index('_verifier(params, a0_tilde'); j=s.index(';',i)+1
s=s[:j]+'\n  g_dbg_a0_ok = memcmp(g_dbg_a0, a0_tilde, params->lambda_bytes)==0; fprintf(stderr,"[a0check] signer a0 == verifier a0 : %s\\n", g_dbg_a0_ok?"YES":"NO");\n'+s[j:]
open(p,'w').write(s)
