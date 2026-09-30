# Diagnostic fix for uBlockith-EM: skip the secret input block already passed as `in`
# when handing the encryption witness to the enc-constraint routines. Apply to utils_ublock/ublockith_ublock_256.c
import sys
p=sys.argv[1]; s=open(p).read()
old_p='out_tag, w + lke_bytes, w_tag + lke_bits, k_bar, k_bar_tag);\n    ublock_hash_deg3_constraints(hasher, o_enc_deg0, o_enc_deg1, o_enc_deg2, UBLOCK_ENC_O_BITS);\n  } else {'
assert s.count(old_p)==1
s=s.replace(old_p,'out_tag, w + lke_bytes + UBLOCK_BLOCK, w_tag + lke_bits + UBLOCK_BLOCK_BITS, k_bar, k_bar_tag); /* EMFIX */\n    ublock_hash_deg3_constraints(hasher, o_enc_deg0, o_enc_deg1, o_enc_deg2, UBLOCK_ENC_O_BITS);\n  } else {')
old_v='ublock_SSS_enc_constraints_verifier(o_enc_key, in_key, out_key, w_key + lke_bits,\n                                        k_bar_key, delta);'
assert s.count(old_v)==1
s=s.replace(old_v,'ublock_SSS_enc_constraints_verifier(o_enc_key, in_key, out_key, w_key + lke_bits + UBLOCK_BLOCK_BITS, /* EMFIX */\n                                        k_bar_key, delta);')
open(p,'w').write(s)
