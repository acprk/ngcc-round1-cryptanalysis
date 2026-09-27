/* finish.c  Public-relation finisher.  Modes:
   dump   : rebuild M (512x512) and B (512) from pk; read /tmp/sh_U.txt (shat + uncertain set U);
            write /tmp/bdd.txt = M_U (512 x |U|) and rhs = B - M*shat  for the sage BDD solver.
   verify : read /tmp/y_rec.txt (y = s_U - shat_U on U), apply to shat, check E bounded, score vs
            true secret, and decrypt 200 fresh honest ciphertexts with the recovered key.
   sk used ONLY to score / final verify, never to guide. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "params.h"
#include "KEM_AlgorithmInstance.h"
#include "pke.h"
#include "poly.h"
#include "ntt.h"
#include "sample.h"
#include "drng.h"

DRNG_ctx drng_algorithm;
static int pmod(int a,int m){a%=m; if(a<0)a+=m; return a;}
static int cen(int a){ a=pmod(a,RL_KEM_Q); if(a>RL_KEM_Q/2)a-=RL_KEM_Q; return a; }
static uint8_t PK[20000],SK[40000]; static unsigned long long PKL,SKL;
static int16_t STRUE[RL_KEM_K][RL_KEM_N];
static int16_t Mmat[512][512];
static int16_t Bco[512];

static void build_MB(void){
    polarlac_polymat a_ntt; poly_generate_uniformQ(&a_ntt,PK,0);
    polarlac_polyvec b_ntt; polyvec_decompress(&b_ntt,PK+PK_SEED_LEN_BYTES);
    for(int i=0;i<RL_KEM_K;i++){ int16_t tmp[RL_KEM_N];
        for(int t=0;t<RL_KEM_N;t++)tmp[t]=b_ntt.vec[i].coeffs[t]; mq_poly_intt(tmp);
        for(int t=0;t<RL_KEM_N;t++)Bco[i*RL_KEM_N+t]=(int16_t)cen(tmp[t]); }
    for(int p=0;p<RL_KEM_K;p++)for(int c=0;c<RL_KEM_N;c++){
        int16_t unit[RL_KEM_N]; memset(unit,0,sizeof(unit)); unit[c]=1; mq_poly_ntt(unit);
        for(int i=0;i<RL_KEM_K;i++){ int16_t prod[RL_KEM_N];
            mq_poly_pointwise_mul(prod,a_ntt.row[i].vec[p].coeffs,unit); mq_poly_intt(prod);
            for(int t=0;t<RL_KEM_N;t++) Mmat[i*RL_KEM_N+t][p*RL_KEM_N+c]=(int16_t)cen(prod[t]); }
    }
}

int main(int argc,char**argv){
    uint8_t seed[64]={0x5a}; init_random_number(&drng_algorithm,seed,64);
    kem_keygen(PK,&PKL,SK,&SKL);
    { const int16_t *sn=(const int16_t*)SK;
      for(int k=0;k<RL_KEM_K;k++){int16_t tmp[RL_KEM_N];
        for(int i=0;i<RL_KEM_N;i++)tmp[i]=sn[k*RL_KEM_N+i]; mq_poly_intt(tmp);
        for(int i=0;i<RL_KEM_N;i++)STRUE[k][i]=(int16_t)cen(tmp[i]); } }
    { FILE*sf=fopen("/tmp/strue.txt","w"); for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)fprintf(sf,"%d ",STRUE[k][i]); fclose(sf); }
    build_MB();
    /* sanity */
    { int8_t st[512]; for(int k=0;k<RL_KEM_K;k++)for(int i=0;i<RL_KEM_N;i++)st[k*RL_KEM_N+i]=(int8_t)STRUE[k][i];
      int bad=0; for(int o=0;o<512;o++){ long acc=Bco[o]; for(int in=0;in<512;in++)acc-=(long)Mmat[o][in]*st[in];
          if(abs(cen((int)(acc%RL_KEM_Q)))>1)bad++; }
      printf("[sanity] true-secret out-of-bound: %d/512\n",bad); }

    int8_t sh[512];
    /* read sh + U */
    FILE*f=fopen("/tmp/sh_U.txt","r"); int nu; if(fscanf(f,"%d",&nu)!=1){printf("bad sh_U\n");return 1;}
    for(int i=0;i<512;i++){int v; fscanf(f,"%d",&v); sh[i]=(int8_t)v;}
    int *U=malloc(sizeof(int)*nu); for(int j=0;j<nu;j++)fscanf(f,"%d",&U[j]); fclose(f);
    int sc=0; for(int o=0;o<512;o++){int k=o/RL_KEM_N,i=o%RL_KEM_N; if(sh[o]==STRUE[k][i])sc++;}
    printf("[finish] shat correct=%d/512  |U|=%d\n",sc,nu);

    if(argc>1 && !strcmp(argv[1],"dump")){
        /* rhs = B - M*shat ; dump M_U (512 x nu) and rhs */
        int rhs[512]; for(int o=0;o<512;o++){ long acc=Bco[o]; for(int in=0;in<512;in++)acc-=(long)Mmat[o][in]*sh[in];
            rhs[o]=cen((int)(acc%RL_KEM_Q)); }
        FILE*g=fopen("/tmp/bdd.txt","w"); fprintf(g,"%d %d %d\n",nu,RL_KEM_Q,512);
        for(int o=0;o<512;o++){ for(int j=0;j<nu;j++)fprintf(g,"%d ",Mmat[o][U[j]]); }
        fprintf(g,"\n"); for(int o=0;o<512;o++)fprintf(g,"%d ",rhs[o]); fprintf(g,"\n"); fclose(g);
        printf("[dump] wrote /tmp/bdd.txt (nu=%d)\n",nu); return 0;
    }
    if(argc>1 && !strcmp(argv[1],"enum")){
        /* enumerate s on U in {-1,0,1}^|U| (bounded); find assignment with 0 out-of-bound E
           in the public relation b=A*s+e. Incremental residual. Then verify decryption. */
        if(nu>16){ printf("|U|=%d too large for enum\n",nu); return 1; }
        int base_out=0; int R0[512];
        for(int o=0;o<512;o++){ long acc=Bco[o]; for(int in=0;in<512;in++)acc-=(long)Mmat[o][in]*sh[in];
            R0[o]=cen((int)(acc%RL_KEM_Q)); if(abs(R0[o])>1)base_out++; }
        printf("[enum] base out-of-bound=%d, enumerating 3^%d assignments on U...\n",base_out,nu);
        long total=1; for(int j=0;j<nu;j++)total*=3;
        int8_t bestS[16]; int bestbad=1<<30;
        for(long code=0;code<total;code++){
            int R[512]; for(int o=0;o<512;o++)R[o]=R0[o];
            long c=code; int8_t sv[16];
            for(int j=0;j<nu;j++){ int val=(int)(c%3)-1; c/=3; sv[j]=(int8_t)val;
                int delta=val - sh[U[j]];
                if(delta) for(int o=0;o<512;o++) R[o]=cen(R[o]-Mmat[o][U[j]]*delta); }
            int bad=0; for(int o=0;o<512;o++) if(abs(R[o])>1){bad++; if(bad>=bestbad)break;}
            if(bad<bestbad){bestbad=bad; memcpy(bestS,sv,nu);}
            if(bad==0) break;
        }
        printf("[enum] best out-of-bound=%d\n",bestbad);
        for(int j=0;j<nu;j++) sh[U[j]]=bestS[j];
        int sc2=0; for(int o=0;o<512;o++){int k=o/RL_KEM_N,i=o%RL_KEM_N; if(sh[o]==STRUE[k][i])sc2++;}
        printf("[enum] after finish: correct=%d/512  (E out-of-bound=%d)\n",sc2,bestbad);
        uint8_t sk2[40000]; memcpy(sk2,SK,SKL); int16_t *sn=(int16_t*)sk2;
        for(int k=0;k<RL_KEM_K;k++){ int16_t tmp[RL_KEM_N];
            for(int i=0;i<RL_KEM_N;i++)tmp[i]=sh[k*RL_KEM_N+i]; mq_poly_ntt(tmp);
            for(int i=0;i<RL_KEM_N;i++)sn[k*RL_KEM_N+i]=tmp[i]; }
        int ok=1; for(int t=0;t<200;t++){ uint8_t s1[128],s2[128],ct[20000]; unsigned long long sl,cl;
            kem_enc(PK,PKL,s1,&sl,ct,&cl); kem_dec(sk2,SKL,ct,cl,s2,&sl);
            if(memcmp(s1,s2,SS_KEY_BYTES)){ok=0;break;} }
        printf("[enum] decrypt-with-recovered-key (200 fresh cts): %s\n",ok?"SUCCESS":"FAIL");
        return 0;
    }
    if(argc>1 && !strcmp(argv[1],"verify")){
        int *y=malloc(sizeof(int)*nu); FILE*h=fopen("/tmp/y_rec.txt","r");
        for(int j=0;j<nu;j++) if(fscanf(h,"%d",&y[j])!=1){printf("bad y\n");return 1;} fclose(h);
        for(int j=0;j<nu;j++){ int o=U[j]; sh[o]=(int8_t)(sh[o]+y[j]); }
        int sc2=0; for(int o=0;o<512;o++){int k=o/RL_KEM_N,i=o%RL_KEM_N; if(sh[o]==STRUE[k][i])sc2++;}
        int bad=0; for(int o=0;o<512;o++){ long acc=Bco[o]; for(int in=0;in<512;in++)acc-=(long)Mmat[o][in]*sh[in];
            if(abs(cen((int)(acc%RL_KEM_Q)))>1)bad++; }
        printf("[verify] after BDD: correct=%d/512  out-of-bound-E=%d/512\n",sc2,bad);
        uint8_t sk2[40000]; memcpy(sk2,SK,SKL); int16_t *sn=(int16_t*)sk2;
        for(int k=0;k<RL_KEM_K;k++){ int16_t tmp[RL_KEM_N];
            for(int i=0;i<RL_KEM_N;i++)tmp[i]=sh[k*RL_KEM_N+i]; mq_poly_ntt(tmp);
            for(int i=0;i<RL_KEM_N;i++)sn[k*RL_KEM_N+i]=tmp[i]; }
        int ok=1; for(int t=0;t<200;t++){ uint8_t s1[128],s2[128],ct[20000]; unsigned long long sl,cl;
            kem_enc(PK,PKL,s1,&sl,ct,&cl); kem_dec(sk2,SKL,ct,cl,s2,&sl);
            if(memcmp(s1,s2,SS_KEY_BYTES)){ok=0;break;} }
        printf("[verify] decrypt-with-recovered-key (200 fresh cts): %s\n",ok?"SUCCESS":"FAIL");
        return 0;
    }
    printf("usage: finish dump|verify\n"); return 0;
}
