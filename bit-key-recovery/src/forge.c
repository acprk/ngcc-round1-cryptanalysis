/* Complete break: read pk.bin (public) + s0_rec.bin (recovered by deconvolved estimator,
 * public data only). Public-relation finisher (b=A*s0+e, e ternary, b0 in [-8,7]) fixes any
 * residual coords, derives e,b0, reconstructs sk, and forges under the UNMODIFIED ref verifier. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"
#include "packing.h"
#include "symmetric.h"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
#define N BIT_N
#define L BIT_L
#define K BIT_K
static poly_matrix_ntt A_ntt; static int16_t b1pub[K][N];
static int cq(int32_t x){x%=BIT_Q;if(x<0)x+=BIT_Q;if(x>BIT_Q/2)x-=BIT_Q;return x;}
static void As0(int16_t s0[L][N],int16_t out[K][N]){
  polyvecl s;for(int i=0;i<L;i++)for(int k=0;k<N;k++)s.vec[i].coeffs[k]=s0[i][k];
  polyvecl_ntt sn;polyvecl_to_ntt(&sn,&s);polyveck b;poly_matrix_mul_vector_ntt(&b,&A_ntt,&sn);
  for(int r=0;r<K;r++)for(int k=0;k<N;k++)out[r][k]=(int16_t)cq((int32_t)b.vec[r].coeffs[k]);}
static int consist(int16_t v[K][N]){int g=0;for(int r=0;r<K;r++)for(int k=0;k<N;k++){
  int R=cq((int32_t)16*b1pub[r][k]-v[r][k]); if(R>=-8&&R<=9)g++;}return g;}
int main(void){
  unsigned char pk[BIT_PUBLICKEYBYTES];FILE*fp=fopen("pk.bin","rb");
  if(fread(pk,1,BIT_PUBLICKEYBYTES,fp)!=BIT_PUBLICKEYBYTES)return 1;fclose(fp);
  unsigned char seedA[BIT_SEEDBYTES];polyveck b1v;unpack_pk(seedA,&b1v,pk);
  poly_matrix_expand_ntt(&A_ntt,seedA);
  for(int r=0;r<K;r++)for(int k=0;k<N;k++)b1pub[r][k]=b1v.vec[r].coeffs[k];
  int16_t s0[L][N];FILE*fr=fopen("s0_rec.bin","rb");
  for(int i=0;i<L;i++)if(fread(s0[i],2,N,fr)!=N)return 1;fclose(fr);
  int16_t v[K][N];As0(s0,v);int g=consist(v);printf("init consistency %d/%d\n",g,K*N);
  /* exhaustive 1-coord fix requiring FULL 768/768 (single error case) */
  if(g<K*N){int found=0;
    for(int i=0;i<L&&!found;i++)for(int k=0;k<N&&!found;k++){int cur=s0[i][k];
      for(int val=-1;val<=1;val++){if(val==cur)continue;s0[i][k]=val;As0(s0,v);
        if(consist(v)==K*N){found=1;break;}}
      if(!found)s0[i][k]=cur;}
    if(found)printf("1-coord fix: SUCCESS full consistency\n");
    else printf("1-coord fix: none; trying 2-coord...\n");
  }
  As0(s0,v);g=consist(v);
  if(g<K*N){/* 2-coord fallback */int found=0;
    for(int i=0;i<L&&!found;i++)for(int k=0;k<N&&!found;k++){int c1=s0[i][k];
      for(int v1=-1;v1<=1&&!found;v1++){if(v1==c1)continue;s0[i][k]=v1;
        for(int i2=0;i2<L&&!found;i2++)for(int k2=0;k2<N&&!found;k2++){int c2=s0[i2][k2];
          for(int v2=-1;v2<=1;v2++){if(v2==c2)continue;s0[i2][k2]=v2;As0(s0,v);
            if(consist(v)==K*N){found=1;break;}}
          if(!found)s0[i2][k2]=c2;}
      }
      if(!found)s0[i][k]=c1;}
    if(found)printf("2-coord fix: SUCCESS\n"); else printf("2-coord fix: FAILED\n");
  }
  As0(s0,v);g=consist(v);printf("post-finish consistency %d/%d\n",g,K*N);
  /* derive e,b0: decompose_b(A*s0+e)==b1pub */
  polyvecl s;for(int i=0;i<L;i++)for(int k=0;k<N;k++)s.vec[i].coeffs[k]=s0[i][k];
  polyvecl_ntt sn;polyvecl_to_ntt(&sn,&s);polyveck bb;poly_matrix_mul_vector_ntt(&bb,&A_ntt,&sn);
  polyveck ep,b0p,b1pk,s0k_dummy;polyvecl s0p;int efail=0;
  for(int i=0;i<L;i++)for(int k=0;k<N;k++)s0p.vec[i].coeffs[k]=s0[i][k];
  for(int r=0;r<K;r++)for(int k=0;k<N;k++){int found=0;
    for(int ev=-1;ev<=1;ev++){int32_t bv=(int32_t)bb.vec[r].coeffs[k]+ev;bv%=BIT_Q;if(bv<0)bv+=BIT_Q;
      int32_t a=bv,hb=(a+(BIT_GAMMA_B>>1))>>BIT_GAMMA_B_BITS,low=a-hb*BIT_GAMMA_B;
      low-=BIT_Q&(((BIT_Q-1)/2-low)>>31);
      if((int16_t)hb==b1pub[r][k]){ep.vec[r].coeffs[k]=ev;b0p.vec[r].coeffs[k]=(int16_t)low;found=1;break;}}
    if(!found){efail++;ep.vec[r].coeffs[k]=0;b0p.vec[r].coeffs[k]=0;}
    b1pk.vec[r].coeffs[k]=b1pub[r][k];}
  printf("e/b0 unresolved coords=%d\n",efail);(void)s0k_dummy;
  /* reconstruct sk (public pk + recovered s0,e,b0; arbitrary secret_seed) */
  unsigned char tr[BIT_TRBYTES];bit_h256(tr,pk,BIT_PUBLICKEYBYTES);
  unsigned char ss[BIT_SEEDBYTES];memset(ss,0x5A,sizeof ss);
  unsigned char skrec[BIT_SECRETKEYBYTES];
  pack_sk(skrec,seedA,&b1pk,ss,tr,&s0p,&ep,&b0p);
  /* forge */
  unsigned char rs[64];FILE*ur=fopen("/dev/urandom","rb");if(fread(rs,1,64,ur)!=64)return 1;fclose(ur);
  init_random_number(&drng_algorithm,rs,64);
  unsigned long long snl=sig_get_sn_len_bytes();unsigned char*sb=malloc(snl);
  unsigned char m1[32]="FORGERY under recovered BiT key";unsigned char m2[32]="a totally different message!!!!";
  unsigned long long sl=snl;int sr=sig_sign(skrec,BIT_SECRETKEYBYTES,m1,32,sb,&sl);
  int v1=sig_verify(pk,BIT_PUBLICKEYBYTES,sb,sl,m1,32);
  int v2=sig_verify(pk,BIT_PUBLICKEYBYTES,sb,sl,m2,32);
  printf("\n== FORGERY (unmodified reference verifier) ==\n");
  printf("sign rc=%d  verify(correct msg)=%d(0=ACCEPT)  verify(wrong msg)=%d(nonzero=REJECT)\n",sr,v1,v2);
  printf("RESULT: %s\n",(sr==0&&v1==0&&v2!=0)?"COMPLETE BREAK — forgery ACCEPTED by reference verifier":"INCOMPLETE");
  /* SCORING ONLY: compare recovered s0 to true key.bin */
  {int16_t st[L][N];FILE*fk=fopen("key.bin","rb");for(int i=0;i<L;i++)if(fread(st[i],2,N,fk)!=N){}fclose(fk);
   int ex=0;for(int i=0;i<L;i++)for(int k=0;k<N;k++)if(s0[i][k]==st[i][k])ex++;
   printf("[SCORING] final s0 exact %d/768\n",ex);}
  return 0;
}
