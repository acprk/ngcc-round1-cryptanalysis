/* Tins-128 key recovery from ONE signature: ChildNodeGen ignores parent seed,
   so every GGM leaf = f(salt, index) is public; aux = alpha ^ sum(shares) leaks alpha,beta. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SIG_TINS256.h"
#include "drng.h"
#include "auxfunc.h"
#include "params.h"
#include "ff_arith.h"
#include "bavc_commit.h"
DRNG_ctx drng_algorithm;

static void expand_pk(const unsigned char *pk, fe u[N_TUPLE], fe v[N_TUPLE]){
  DRNG_ctx pe; memset(u,0,sizeof(fe)*N_TUPLE); memset(v,0,sizeof(fe)*N_TUPLE);
  init_random_number(&pe,(unsigned char*)pk,PK_SEEDLEN);
  static unsigned char ub[(N_TUPLE*K+7)/8], vb[((N_TUPLE-1)*K+7)/8];
  get_random_number(&pe,ub,N_TUPLE*K); get_random_number(&pe,vb,(N_TUPLE-1)*K);
  fe_decompress(ub,u,N_TUPLE); fe_decompress(vb,v,N_TUPLE-1);
  fe_decompress((unsigned char*)pk+PK_SEEDLEN, v+N_TUPLE-1, 1);
}
/* check NSBC relation (<u,a>+u_{n-2})(<v,b>+v_{n-1}) == (<u,b>+u_{n-1})(<v,a>+v_{n-2}) */
static int check_nsbc(fe u[], fe v[], unsigned char *a, unsigned char *b){
  fe s0,s1,s2,s3,l,r,d;
  fe_f2_inner(u,a,N_TUPLE-2,s0); fe_add(s0,u[N_TUPLE-2],s0);
  fe_f2_inner(v,b,N_TUPLE-2,s1); fe_add(s1,v[N_TUPLE-1],s1);
  fe_f2_inner(u,b,N_TUPLE-2,s2); fe_add(s2,u[N_TUPLE-1],s2);
  fe_f2_inner(v,a,N_TUPLE-2,s3); fe_add(s3,v[N_TUPLE-2],s3);
  fe_mul(s0,s1,l); fe_mul(s2,s3,r); fe_add(l,r,d); return deg(d)==-1;
}
/* forge: same as sig_sign but with externally supplied alpha,beta */
static int forge_sign(const unsigned char *pk, unsigned char *alpha, unsigned char *beta,
    unsigned char *msg, unsigned long long mlen, unsigned char *sn, unsigned long long *snlen){
  fe u[N_TUPLE], v[N_TUPLE]; expand_pk(pk,u,v);
  unsigned char salt[SALT_SIZE], rseed[RSEED_SIZE];
  commitment (*comms)[N] = calloc(TAU, sizeof(commitment[N]));
  static unsigned char aux[TAU][N_TUPLE_SIZE*2]; static ff12b base[TAU][2*N_TUPLE-3]; ff12b delta[TAU];
  hash_t h_sh, h_piop; memset(h_piop,0,sizeof h_piop); fe p_mid[TAU], p_base[TAU];
  memset(p_base,0,sizeof p_base); memset(p_mid,0,sizeof p_mid); memset(base,0,sizeof base); memset(delta,0,sizeof delta);
  get_random_number(&drng_algorithm,salt,SALT_SIZE*8); get_random_number(&drng_algorithm,rseed,RSEED_SIZE*8);
  node *tree = malloc((2*N_LEAVES-1)*sizeof(node));
  CommitPoly(salt,rseed,tree,comms,alpha,beta,aux,base,delta,h_sh);
  for(int e=0;e<TAU;e++) ComputePoly(alpha,beta,base[e],delta[e],u,v,p_mid[e],p_base[e]);
  int NB = 1+PK_SEEDLEN+SALT_SIZE+mlen+sizeof(hash_t)+(K*2*TAU+K+7)/8;
  unsigned char *nonce=calloc(NB,1); nonce[0]=2; memcpy(nonce+1,pk,PK_SEEDLEN);
  memcpy(nonce+1+PK_SEEDLEN,salt,SALT_SIZE); memcpy(nonce+1+PK_SEEDLEN+SALT_SIZE,msg,mlen);
  memcpy(nonce+1+PK_SEEDLEN+SALT_SIZE+mlen,h_sh,sizeof(hash_t)); int off=1+PK_SEEDLEN+SALT_SIZE+mlen+sizeof(hash_t);
  fe p_tmp[2*TAU+1]; memcpy(p_tmp,p_mid,TAU*sizeof(fe)); memcpy(p_tmp+TAU,p_base,TAU*sizeof(fe)); memcpy(p_tmp+2*TAU,v+N_TUPLE-1,sizeof(fe)); fe_compress(p_tmp,2*TAU+1,nonce+off);
  pseudohash(sizeof(hash_t)*8,nonce,(1+PK_SEEDLEN+SALT_SIZE+mlen+sizeof(hash_t))*8+K*2*TAU+K,h_piop); free(nonce);
  long long ctr; int ps; node path[T_OPEN]; commitment proof[TAU];
  OpenRandomEva(tree,comms,h_piop,&ctr,path,&ps,proof);
  int pos=0; memcpy(sn,salt,SALT_SIZE); pos+=SALT_SIZE; memcpy(sn+pos,&ctr,8); pos+=8;
  memcpy(sn+pos,h_piop,sizeof(hash_t)); pos+=sizeof(hash_t); memcpy(sn+pos,path,NODE_SIZE*ps); pos+=NODE_SIZE*ps;
  memcpy(sn+pos,proof,sizeof(commitment)*TAU); pos+=sizeof(commitment)*TAU;
  fe_compress(p_mid,TAU,sn+pos); pos+=TAU*K/8; compress_aux(aux,TAU,sn+pos);
  *snlen = pos+((N_TUPLE-2)*TAU*2+7)/8; free(tree); free(comms); return 0;
}
static int rdhex(const char*f,unsigned char*b){FILE*F=fopen(f,"r");int n=0;unsigned x;while(fscanf(F,"%2x",&x)==1)b[n++]=x;fclose(F);return n;}
int main(int argc,char**argv){
  if(argc>2){ unsigned char pk[PK_SIZE]; unsigned char *sn=calloc(SIG_SIZE+64,1); rdhex(argv[1],pk); unsigned long long snl=rdhex(argv[2],sn);
    static unsigned char aux[TAU][N_TUPLE_SIZE*2]; decompress_aux(sn+snl-((N_TUPLE-2)*TAU*2+7)/8,aux,TAU);
    node *tree=malloc((2*N_LEAVES-1)*sizeof(node)); commitment (*coms)[N]=calloc(TAU,sizeof(commitment[N])); node (*seeds)[N]=calloc(TAU,sizeof(node[N])); hash_t Hc; unsigned char dr[RSEED_SIZE]={0};
    bavc_commit(sn,dr,tree,coms,Hc,seeds); unsigned char aacc[N_TUPLE_SIZE]={0},bacc[N_TUPLE_SIZE]={0},buf[(MU+2*N_TUPLE-4+7)/8];
    for(int i=0;i<N;i++){DRNG_ctx se;unsigned char nn[SALT_SIZE+NODE_SIZE];memcpy(nn,sn,SALT_SIZE);memcpy(nn+SALT_SIZE,seeds[0][i],NODE_SIZE);init_random_number(&se,nn,SALT_SIZE+NODE_SIZE);get_random_number(&se,buf,MU+2*N_TUPLE-4);
      for(int j=0;j<N_TUPLE_SIZE;j++){unsigned char a=buf[j],b=buf[N_TUPLE_SIZE+j];if(j==N_TUPLE_SIZE-1){a&=0xc0;b&=0xc0;}aacc[j]^=a;bacc[j]^=b;}}
    unsigned char al[N_TUPLE_SIZE],be[N_TUPLE_SIZE]; for(int j=0;j<N_TUPLE_SIZE;j++){al[j]=aux[0][j]^aacc[j];be[j]=aux[0][N_TUPLE_SIZE+j]^bacc[j];}
    fe u[N_TUPLE],v[N_TUPLE]; expand_pk(pk,u,v); printf("[KAT] sig bytes %llu; recovered witness satisfies NSBC: %s\nalpha=",snl,check_nsbc(u,v,al,be)?"YES":"no"); for(int j=0;j<N_TUPLE_SIZE;j++)printf("%02x",al[j]); printf("\n"); return 0; }

  unsigned char seed[64]; for(int i=0;i<64;i++) seed[i]=0xA5^i;
  init_random_number(&drng_algorithm,seed,64);
  unsigned long long pkl,skl,snl=SIG_SIZE; unsigned char pk[PK_SIZE], sk[SK_SIZE]; unsigned char *sn=calloc(SIG_SIZE+64,1);
  sig_keygen(pk,&pkl,sk,&skl);
  unsigned char msg[32]="victim message";
  sig_sign(sk,skl,msg,32,sn,&snl);
  printf("[victim] honest sig len %llu, verify=%d\n",snl,sig_verify(pk,pkl,sn,snl,msg,32));
  /* ---- attacker: sees pk, sn only ---- */
  unsigned char *salt = sn; static unsigned char aux[TAU][N_TUPLE_SIZE*2];
  decompress_aux(sn + snl - ((N_TUPLE-2)*TAU*2+7)/8, aux, TAU);
  node *tree=malloc((2*N_LEAVES-1)*sizeof(node)); commitment (*coms)[N]=calloc(TAU,sizeof(commitment[N]));
  node (*seeds)[N]=calloc(TAU,sizeof(node[N])); hash_t Hc; unsigned char dummyroot[RSEED_SIZE]={0};
  bavc_commit(salt,dummyroot,tree,coms,Hc,seeds);   /* root value irrelevant */
  unsigned char aacc[N_TUPLE_SIZE]={0}, bacc[N_TUPLE_SIZE]={0}, buf[(MU+2*N_TUPLE-4+7)/8];
  int e=0;
  for(int i=0;i<N;i++){ DRNG_ctx se; unsigned char nn[SALT_SIZE+NODE_SIZE]; memcpy(nn,salt,SALT_SIZE); memcpy(nn+SALT_SIZE,seeds[e][i],NODE_SIZE);
    init_random_number(&se,nn,SALT_SIZE+NODE_SIZE); get_random_number(&se,buf,MU+2*N_TUPLE-4);
    for(int j=0;j<N_TUPLE_SIZE;j++){ unsigned char a=buf[j], b=buf[N_TUPLE_SIZE+j]; if(j==N_TUPLE_SIZE-1){a&=0xc0;b&=0xc0;} aacc[j]^=a; bacc[j]^=b; } }
  unsigned char alpha[N_TUPLE_SIZE], beta[N_TUPLE_SIZE];
  for(int j=0;j<N_TUPLE_SIZE;j++){ alpha[j]=aux[e][j]^aacc[j]; beta[j]=aux[e][N_TUPLE_SIZE+j]^bacc[j]; }
  fe u[N_TUPLE], v[N_TUPLE]; expand_pk(pk,u,v);
  printf("[attacker] recovered (alpha,beta) satisfies NSBC for pk: %s\n", check_nsbc(u,v,alpha,beta)?"YES":"no");
  /* cross-check with repetition e=1 */
  memset(aacc,0,sizeof aacc); for(int i=0;i<N;i++){ DRNG_ctx se; unsigned char nn[SALT_SIZE+NODE_SIZE]; memcpy(nn,salt,SALT_SIZE); memcpy(nn+SALT_SIZE,seeds[1][i],NODE_SIZE);
    init_random_number(&se,nn,SALT_SIZE+NODE_SIZE); get_random_number(&se,buf,MU+2*N_TUPLE-4); for(int j=0;j<N_TUPLE_SIZE;j++){unsigned char a=buf[j]; if(j==N_TUPLE_SIZE-1)a&=0xc0; aacc[j]^=a;} }
  int same=1; for(int j=0;j<N_TUPLE_SIZE;j++) if((aux[1][j]^aacc[j])!=alpha[j]) same=0;
  printf("[attacker] repetition 1 gives same alpha: %s\n", same?"YES":"no");
  unsigned char fmsg[32]="attacker-chosen forged message!"; unsigned char *fs=calloc(SIG_SIZE+64,1); unsigned long long fl;
  forge_sign(pk,alpha,beta,fmsg,32,fs,&fl);
  printf("[attacker] forged sig len %llu, verify(pk, forged msg)=%d (0=accept)\n",fl,sig_verify(pk,pkl,fs,fl,fmsg,32));
  unsigned char wmsg[32]="different-message-control!!"; printf("[attacker] CONTROL wrong-msg verify=%d (nonzero=reject)\n", sig_verify(pk,pkl,fs,fl,wmsg,32));
  return 0; }
