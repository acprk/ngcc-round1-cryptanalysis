/* dump f,g,F,G,u_hat,A_hat(00,01,10,11) as doubles (SCORING/diagnostic only) */
#include <stdio.h>
#include <stdlib.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#include "yuanyang_inner.h"
DRNG_ctx drng_algorithm;
#define D YUANYANG_D
static double fd(fpr x){return (double)(int64_t)x.v/8796093022208.0;}
int main(int argc,char**argv){int ks=atoi(argv[1]);
  unsigned long long pkl=sig_get_pk_len_bytes(),skl=sig_get_sk_len_bytes();
  unsigned char *pk=malloc(pkl),*sk=malloc(skl);
  unsigned char seed[64]; for(int i=0;i<64;i++) seed[i]=(unsigned char)("gapstatYYseed!!!"[i%16]+ks*(i==0));
  init_random_number(&drng_algorithm,seed,64); sig_keygen(pk,&pkl,sk,&skl);
  static yuanyang_expanded_sk e; yuanyang_decode_private_key(&e,sk,skl);
  for(int i=0;i<D;i++) printf("%d %d %d %d %.12f %.12f %.12f %.12f %.12f\n",e.compact.f[i],e.compact.g[i],e.compact.F[i],e.compact.G[i],fd(e.u_hat[i]),
     fd(e.A_hat[0*D+i]),fd(e.A_hat[1*D+i]),fd(e.A_hat[2*D+i]),fd(e.A_hat[3*D+i]));
}
