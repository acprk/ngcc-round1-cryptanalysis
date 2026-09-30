/* gapstat: transcript statistics for YuanYang.DSA through the full signing API.
 * s1 decoded from the released signature, s2 = centerlift(m + h*s1) as the verifier does.
 * sk read ONLY to build scoring directions (SCORING).  argv: N keyseed [nullN] */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <complex.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#include "yuanyang_inner.h"
DRNG_ctx drng_algorithm;
#define D YUANYANG_D
static double complex W[D]; /* zeta^{i}, zeta=e^{i pi/D} */
static void ndft(const double *x, double complex *X){ /* X[k]=sum x_i w_k^i, w_k=zeta^{2k+1}; radix-2 FFT after twist */
  double complex a[D]; for(int i=0;i<D;i++) a[i]=x[i]*W[i];
  for(int i=1,j=0;i<D;i++){int b=D>>1;for(;j&b;b>>=1)j^=b;j^=b;if(i<j){double complex t=a[i];a[i]=a[j];a[j]=t;}}
  for(int len=2;len<=D;len<<=1){double complex wl=cexp(2*M_PI*I/len);
    for(int i=0;i<D;i+=len){double complex w=1;for(int k=0;k<len/2;k++){double complex u=a[i+k],v=a[i+k+len/2]*w;a[i+k]=u+v;a[i+k+len/2]=u-v;w*=wl;}}}
  for(int k=0;k<D;k++) X[k]=a[k]; /* X[k] = sum x_i zeta^i e^{2pi i ik/D} = sum x_i zeta^{i(2k+1)} */
}
static double complex M11[D],M22[D],M12[D];
static double Rdir(const double *d1,const double *d2,double sig2){
  double complex A[D],B[D]; ndft(d1,A); ndft(d2,B); double num=0,nn=0;
  for(int k=0;k<D;k++){ num += creal(conj(A[k])*M11[k]*A[k] + conj(B[k])*M22[k]*B[k] + 2*creal(conj(A[k])*M12[k]*B[k])); }
  for(int i=0;i<D;i++) nn+=d1[i]*d1[i]+d2[i]*d2[i];
  return num/((double)D*D)/(sig2*nn);
}
int main(int argc,char**argv){
  long N=argc>1?atol(argv[1]):20000; int ks=argc>2?atoi(argv[2]):0; int nnull=argc>3?atoi(argv[3]):40;
  for(int i=0;i<D;i++) W[i]=cexp(I*M_PI*i/D);
  unsigned long long pkl=sig_get_pk_len_bytes(),skl=sig_get_sk_len_bytes(),snl=sig_get_sn_len_bytes();
  unsigned char *pk=malloc(pkl),*sk=malloc(skl),*sn=malloc(snl);
  unsigned char seed[64]; for(int i=0;i<64;i++) seed[i]=(unsigned char)("gapstatYYseed!!!"[i%16]+ks*(i==0));
  init_random_number(&drng_algorithm,seed,64);
  if(sig_keygen(pk,&pkl,sk,&skl)){fprintf(stderr,"keygen\n");return 1;}
  static yuanyang_expanded_sk esk; yuanyang_decode_private_key(&esk,sk,skl); /* SCORING */
  uint16_t h[D]; yuanyang_decode_public_key(h,pk,pkl);
  double *mu=calloc(2*D,sizeof(double)); double sq1=0,sq2=0;
  yuanyang_sign_stats tot; memset(&tot,0,sizeof tot); long bad=0;
  for(long n=0;n<N;n++){
    unsigned char msg[16]; for(int i=0;i<16;i++) msg[i]=(unsigned char)((n>>(8*(i%8)))+i*37+ks);
    yuanyang_sign_stats st; unsigned long long L=snl;
    if(yuanyang_sign_core_with_stats(sk,skl,msg,16,sn,&L,&st)){bad++;continue;}
    tot.attempts+=st.attempts;tot.delta1_reject+=st.delta1_reject;tot.delta2_reject+=st.delta2_reject;
    tot.squared_norm_reject+=st.squared_norm_reject;tot.compression_reject+=st.compression_reject;tot.success+=st.success;
    /* verifier-side reconstruction */
    int16_t s1[D]; if(yuanyang_decode_signature_s1(s1,sn,L)){bad++;continue;}
    unsigned char sd[32]; yuanyang_hash_message_with_public_key(sd,msg,16,h);
    uint16_t c[D]; yuanyang_hash_to_challenge(c,sn,sd);
    uint16_t hs[D]; yuanyang_mul_mod_xn_plus_1(hs,h,s1);
    double x1[D],x2[D];
    for(int i=0;i<D;i++){ x1[i]=s1[i]; x2[i]=yuanyang_center_lift_q((uint16_t)((c[i]+hs[i])%YUANYANG_Q));
      mu[i]+=x1[i]; mu[D+i]+=x2[i]; sq1+=x1[i]*x1[i]; sq2+=x2[i]*x2[i]; }
    double complex X1[D],X2[D]; ndft(x1,X1); ndft(x2,X2);
    for(int k=0;k<D;k++){M11[k]+=X1[k]*conj(X1[k]);M22[k]+=X2[k]*conj(X2[k]);M12[k]+=X1[k]*conj(X2[k]);}
  }
  long G=N-bad; for(int k=0;k<D;k++){M11[k]/=G;M22[k]/=G;M12[k]/=G;}
  for(int i=0;i<2*D;i++) mu[i]/=G;
  double v1=sq1/G/D,v2=sq2/G/D,sig2=(v1+v2)/2;
  printf("key%d N=%ld bad=%ld  sigma_hat^2=%.1f (target 4866.5 @69.76)  s1 var %.1f  s2 var %.1f  ratio %.4f\n",ks,G,bad,sig2,v1,v2,v2/v1);
  printf("  per-sig attempts: %.4f  delta1_rej %.5f delta2_rej %.5f norm_rej %.5f compress_rej %.5f (per signature)\n",
    (double)tot.attempts/G,(double)tot.delta1_reject/G,(double)tot.delta2_reject/G,(double)tot.squared_norm_reject/G,(double)tot.compression_reject/G);
  /* first moment: under zero-mean, sum mu_i^2 * G/sig2 ~ chi2_{2D} */
  double mm1=0,mm2=0; for(int i=0;i<D;i++){mm1+=mu[i]*mu[i];mm2+=mu[D+i]*mu[D+i];}
  double chi=(mm1+mm2)*G/sig2; printf("  MEAN: rms(mu1)=%.3f rms(mu2)=%.3f  chi2=%.1f on %d dof -> z=%.1f\n",sqrt(mm1/D),sqrt(mm2/D),chi,2*D,(chi-2*D)/sqrt(4.0*D));
  printf("  mu1[0..5]= %.2f %.2f %.2f %.2f %.2f %.2f   mu2[0..5]= %.2f %.2f %.2f %.2f %.2f %.2f\n",mu[0],mu[1],mu[2],mu[3],mu[4],mu[5],mu[D],mu[D+1],mu[D+2],mu[D+3],mu[D+4],mu[D+5]);
  FILE*fm=fopen(argc>4?argv[4]:"/dev/null","w"); if(fm){for(int i=0;i<2*D;i++)fprintf(fm,"%.6f\n",mu[i]);fclose(fm);}
  /* s1 autocorr from M11: P1[j]=(1/D) sum_k M11[k] w_k^{-j}... use real part */
  double best=0;int bj=0; double P0=0; for(int k=0;k<D;k++)P0+=creal(M11[k]); 
  for(int j=1;j<D;j++){double complex s=0; for(int k=0;k<D;k++) s+=M11[k]*cpow(W[1],-(double)j*(2*k+1)); double r=fabs(creal(s))/P0; if(r>best){best=r;bj=j;}}
  printf("  s1 autocorr max|P1[j]|/P1[0]=%.5f at j=%d (white floor ~%.1e)\n",best,bj,1/sqrt((double)G*D));
  /* secret directions (SCORING) */
  double f[D],g[D],F[D],Gg[D],mf[D],mg[D],mF[D],mG[D];
  for(int i=0;i<D;i++){f[i]=esk.compact.f[i];g[i]=esk.compact.g[i];F[i]=esk.compact.F[i];Gg[i]=esk.compact.G[i];mf[i]=-f[i];mF[i]=-F[i];}
  (void)mg;(void)mG;
  double Rfg=Rdir(f,g,sig2),Rgf=Rdir(g,mf,sig2),RFG=Rdir(F,Gg,sig2),RGF=Rdir(Gg,mF,sig2);
  /* null: shuffled (f,g) */
  srand(777+ks); double s=0,ss=0;
  for(int t=0;t<nnull;t++){double a[D],b[D];memcpy(a,f,sizeof a);memcpy(b,g,sizeof b);
    for(int i=D-1;i>0;i--){int k=rand()%(i+1);double tt=a[i];a[i]=a[k];a[k]=tt;k=rand()%(i+1);tt=b[i];b[i]=b[k];b[k]=tt;}
    double r=Rdir(a,b,sig2);s+=r;ss+=r*r;}
  double nm=s/nnull,nsd=sqrt(ss/nnull-nm*nm);
  printf("  R(f,g)=%.4f z=%+.1f | R(g,-f)=%.4f z=%+.1f | R(F,G)=%.4f z=%+.1f | R(G,-F)=%.4f z=%+.1f | null %.4f+-%.4f (n=%d)\n",
    Rfg,(Rfg-nm)/nsd,Rgf,(Rgf-nm)/nsd,RFG,(RFG-nm)/nsd,RGF,(RGF-nm)/nsd,nm,nsd,nnull);
  if(argc>5){FILE*fo=fopen(argv[5],"w"); /* dump: k, M11, M22, ReM12, ImM12, F(f),F(g),F(F),F(G) re/im (SCORING) */
    double complex Ff[D],Fg[D],FF[D],FG[D]; ndft(f,Ff);ndft(g,Fg);ndft(F,FF);ndft(Gg,FG);
    for(int k=0;k<D;k++){double complex c11=M11[k]-0,c22=M22[k],c12=M12[k];
      fprintf(fo,"%d %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f %.6f\n",k,creal(c11),creal(c22),creal(c12),cimag(c12),
        creal(Ff[k]),cimag(Ff[k]),creal(Fg[k]),cimag(Fg[k]),creal(FF[k]),cimag(FF[k]),creal(FG[k]),cimag(FG[k]));}
    fclose(fo);}
  return 0;
}
