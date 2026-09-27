/* Fixed keygen seed (shared across workers); independent signing randomness per worker.
 * argv: T sigfile writemeta(0/1). Worker with writemeta=1 also dumps pk.bin/key.bin/sk.bin. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#include "packing.h"
#include "poly.h"
#include "polyvec.h"
#include "params.h"
DRNG_ctx drng_algorithm;
int main(int argc,char**argv){
  long T=atol(argv[1]); const char*sigf=argv[2]; int meta=atoi(argv[3]);
  unsigned char kseed[64]; for(int i=0;i<64;i++)kseed[i]=(unsigned char)(0xA7*i+0x13);
  init_random_number(&drng_algorithm,kseed,64);
  unsigned long long pkl=sig_get_pk_len_bytes(),skl=sig_get_sk_len_bytes(),snl=sig_get_sn_len_bytes();
  unsigned char*pk=malloc(pkl),*sk=malloc(skl),*sn=malloc(snl);
  sig_keygen(pk,&pkl,sk,&skl);
  if(meta){
    FILE*fp=fopen("pk.bin","wb");fwrite(pk,1,pkl,fp);fclose(fp);
    FILE*fsk=fopen("sk.bin","wb");fwrite(sk,1,skl,fsk);fclose(fsk);
    unsigned char seedA[BIT_SEEDBYTES],ss[BIT_SEEDBYTES],tr[BIT_TRBYTES];
    polyveck b1,e,b0;polyvecl s0; unpack_sk(seedA,&b1,ss,tr,&s0,&e,&b0,sk);
    FILE*fk=fopen("key.bin","wb");
    for(int i=0;i<BIT_L;i++)fwrite(s0.vec[i].coeffs,2,BIT_N,fk);
    for(int i=0;i<BIT_K;i++)fwrite(e.vec[i].coeffs,2,BIT_N,fk);
    for(int i=0;i<BIT_K;i++)fwrite(b0.vec[i].coeffs,2,BIT_N,fk);
    fclose(fk);
  }
  /* reseed for independent signing randomness */
  unsigned char rs[64]; FILE*ur=fopen("/dev/urandom","rb"); if(fread(rs,1,64,ur)!=64)return 1; fclose(ur);
  init_random_number(&drng_algorithm,rs,64);
  srand((unsigned)(getpid()^time(NULL)));
  FILE*fs=fopen(sigf,"wb");
  unsigned char m[32];
  for(long t=0;t<T;t++){
    for(int i=0;i<32;i++)m[i]=(unsigned char)rand();
    unsigned long long s=snl;
    if(sig_sign(sk,skl,m,32,sn,&s)){t--;continue;}
    polyvecm1 z1;polyveck h;unsigned char ch[BIT_CHALLENGEBYTES];poly c;
    unpack_sig(&z1,&h,ch,sn); poly_challenge(&c,ch);
    for(int i=0;i<BIT_L+1;i++)fwrite(z1.vec[i].coeffs,2,BIT_N,fs);
    fwrite(c.coeffs,2,BIT_N,fs);
  }
  fclose(fs); fprintf(stderr,"worker done %ld -> %s\n",T,sigf);
  return 0;
}
