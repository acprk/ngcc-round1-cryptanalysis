# Count nonzero constraint VALUES (clear-text evaluation on the honest witness) in Vistrutith prover.
import sys
p=sys.argv[1]; s=open(p).read()
old='  for (unsigned int i = 0; i < VISTRUTITH_ENC_CSTRNTS_NORM_LEN; ++i) {\n    zk_hash_SSS_3_update(hasher, z_norm_tag[i], z_io0_tag[i], z_io1_tag[i]);\n  }'
assert s.count(old)==1
new=old+'''
  { unsigned nz_n=0,nz_0=0,nz_1=0; uint8_t zb[64]; const uint8_t z0[64]={0};
    for (unsigned int i = 0; i < VISTRUTITH_ENC_CSTRNTS_NORM_LEN; ++i) {
      bfSSS_store(zb, z_norm_val[i]); nz_n += memcmp(zb,z0,64)!=0;
      bfSSS_store(zb, z_io0_val[i]); nz_0 += memcmp(zb,z0,64)!=0;
      bfSSS_store(zb, z_io1_val[i]); nz_1 += memcmp(zb,z0,64)!=0; }
    fprintf(stderr,"[valchk] n=%u nonzero values: norm=%u io0=%u io1=%u\\n",(unsigned)VISTRUTITH_ENC_CSTRNTS_NORM_LEN,nz_n,nz_0,nz_1); }'''
s='#include <stdio.h>\n'+s.replace(old,new)
open(p,'w').write(s)
