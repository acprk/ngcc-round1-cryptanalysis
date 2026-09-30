/* 1-D sampler moment check vs exact discrete Gaussian. */
#include <stdio.h>
#include <math.h>
#include "drng.h"
#include "sampler.h"
DRNG_ctx drng_algorithm;
static int rb(void *ctx, unsigned char *buf, unsigned long long n){return get_random_number((DRNG_ctx*)ctx,buf,8u*n);}
static void exact(double mu,double s,double*m,double*v){double Z=0,M=0,V=0;for(int k=-400;k<=400;k++){double w=exp(-(k-mu)*(k-mu)/(2*s*s));Z+=w;M+=w*k;V+=w*k*k;}*m=M/Z;*v=V/Z-(*m)*(*m);}
static fpr tofpr(double x){fpr r; r.v=(uint64_t)(int64_t)llround(x*8796093022208.0); return r;}
int main(int argc,char**argv){
  long N=argc>1?atol(argv[1]):400000; unsigned char seed[48]={1};
  init_random_number(&drng_algorithm,seed,48); prng rng; prng_init(&rng,rb,&drng_algorithm);
  double eta=1.026;
  { double S=0,S2=0; for(long i=0;i<N;i++){int z;yuanyang_samplerz_large_zero(&z,&rng);S+=z;S2+=(double)z*z;}
    double m=S/N,v=S2/N-m*m,em,ev; printf("large_zero: mean %.4f var %.4f (std %.4f)\n",m,v,sqrt(v));
    exact(0,4*eta,&em,&ev);printf("   exact 4eta var %.4f ; ",ev); exact(0,16*eta,&em,&ev);printf("16eta var %.4f\n",ev);}
  double mus[]={0,0.25,0.5,0.75,3.3,-7.6};
  for(int t=0;t<6;t++){double mu=mus[t];
    double S=0,S2=0; for(long i=0;i<N;i++){int z;yuanyang_samplerz_large(&z,tofpr(mu),&rng);S+=z;S2+=(double)z*z;}
    double m=S/N,v=S2/N-m*m,em4,ev4,em16,ev16; exact(mu,4*eta,&em4,&ev4); exact(mu,16*eta,&em16,&ev16);
    printf("large mu=%5.2f: mean %.4f var %.4f | exact4eta mean %.4f var %.4f | exact16eta var %.4f\n",mu,m,v,em4,ev4,ev16);
    S=0;S2=0; for(long i=0;i<N;i++){int z;yuanyang_samplerz_small(&z,tofpr(mu),&rng);S+=z;S2+=(double)z*z;}
    m=S/N;v=S2/N-m*m; double em,ev; exact(mu,eta,&em,&ev);
    printf("small mu=%5.2f: mean %.4f var %.4f | exact eta mean %.4f var %.4f\n",mu,m,v,em,ev);}
  printf("SE(var)~ var*sqrt(2/N)=%.4f rel\n",sqrt(2.0/N));
}
