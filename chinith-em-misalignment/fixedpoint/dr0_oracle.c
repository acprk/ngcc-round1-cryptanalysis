/* Self-contained uBlock-256/256 key schedule + round, reproduced verbatim
 * from src/.../utils_ublock/{ublock_core.c,ublock_witness.c,ublock.h,ublock_internal.h}.
 * Provides: set_key, round (== ublock_round_witness), build_round_keys, DR0.
 * Cross-validated against the real library core in validate mode. */
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ---- constants (from ublock.h) ---- */
static const uint8_t SBOX[16]={0x7,0x4,0x9,0xc,0xb,0xa,0xd,0x8,0xf,0xe,0x1,0x6,0x0,0x3,0x2,0x5};
static const uint8_t SBOX_BYTE_hi_lo(uint8_t v){return (uint8_t)((SBOX[(v>>4)&0xf]<<4)|SBOX[v&0xf]);}
static const uint8_t pk[32]={10,5,15,0,2,7,8,13,1,14,4,12,9,11,3,6,
                             24,25,26,27,28,29,30,31,16,17,18,19,20,21,22,23};
static const uint32_t RC[24]={
 0x988cc9dd,0xf0e4a1b5,0x21357064,0x8397d2c6,0xc7d39682,0x4f5b1e0a,0x5e4a0f1b,0x7c682d39,
 0x392d687c,0xb3a7e2f6,0xa7b3f6e2,0x8e9adfcb,0xdcc88d99,0x786c293d,0x30246175,0xa1b5f0e4,
 0x8296d3c7,0xc5d19480,0x4a5e1b0f,0x55410410,0x6b7f3a2e,0x17034652,0xeffbbeaa,0x1f0b4e5a};
#define ROUNDS 24

static inline uint32_t rotl32(uint32_t x,unsigned n){return (x<<n)|(x>>((32-n)&31));}
static inline uint32_t ld_be(const uint8_t*b,uint32_t n){b+=4*n;return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];}
static inline void st_be(uint32_t v,uint8_t*b){b[0]=v>>24;b[1]=v>>16;b[2]=v>>8;b[3]=v;}

/* perms (from ublock_internal.h) */
#define B0(w) ((w)>>24)
#define B1(w) (((w)>>16)&0xFFu)
#define B2(w) (((w)>>8)&0xFFu)
#define B3(w) ((w)&0xFFu)
#define PK(a,b,c,d) (((a)<<24)|((b)<<16)|((c)<<8)|(d))
static inline void perm_PL(uint32_t*out,const uint32_t*in){
 uint32_t w0=in[0],w1=in[1],w2=in[2],w3=in[3];
 out[0]=PK(B2(w0),B3(w1),B0(w2),B1(w3));
 out[1]=PK(B3(w0),B2(w1),B1(w2),B0(w3));
 out[2]=PK(B1(w0),B0(w1),B3(w3),B2(w2));
 out[3]=PK(B2(w3),B3(w2),B1(w1),B0(w0));}
static inline void perm_PR(uint32_t*out,const uint32_t*in){
 uint32_t w0=in[0],w1=in[1],w2=in[2],w3=in[3];
 out[0]=PK(B2(w1),B3(w2),B1(w0),B0(w3));
 out[1]=PK(B1(w2),B0(w1),B2(w0),B3(w3));
 out[2]=PK(B3(w1),B0(w0),B1(w3),B2(w2));
 out[3]=PK(B2(w3),B3(w0),B0(w2),B1(w1));}

/* round == ublock_round_witness */
static void round_fn(uint32_t*X0,uint32_t*X1,const uint32_t*rk){
 for(int w=0;w<4;w++){
  uint32_t a=X0[w]^rk[w], b=X1[w]^rk[w+4];
  a=((uint32_t)SBOX_BYTE_hi_lo(a>>24)<<24)|((uint32_t)SBOX_BYTE_hi_lo((a>>16)&0xFF)<<16)
   |((uint32_t)SBOX_BYTE_hi_lo((a>>8)&0xFF)<<8)|SBOX_BYTE_hi_lo(a&0xFF);
  b=((uint32_t)SBOX_BYTE_hi_lo(b>>24)<<24)|((uint32_t)SBOX_BYTE_hi_lo((b>>16)&0xFF)<<16)
   |((uint32_t)SBOX_BYTE_hi_lo((b>>8)&0xFF)<<8)|SBOX_BYTE_hi_lo(b&0xFF);
  b^=a; a^=rotl32(b,4); b^=rotl32(a,8); a^=rotl32(b,8); b^=rotl32(a,20); a^=b;
  X0[w]=a; X1[w]=b;
 }
 uint32_t t0[4],t1[4]; perm_PL(t0,X0); perm_PR(t1,X1);
 memcpy(X0,t0,16); memcpy(X1,t1,16);
}

/* key schedule (from ublock_core.c) */
typedef struct{uint32_t rk[25][8];}ks_t;
static uint8_t gf24_mul2(uint8_t b){return (b&0x08)?(uint8_t)(((b<<1)^0x3)&0x0f):(uint8_t)((b<<1)&0x0f);}
static void apply_tk(uint8_t*d,size_t n){for(size_t i=0;i<n;i++){uint8_t hi=(d[i]>>4)&0xf,lo=d[i]&0xf;d[i]=(uint8_t)((gf24_mul2(hi)<<4)|gf24_mul2(lo));}}
static void apply_sn(uint8_t*d,size_t n){for(size_t i=0;i<n;i++)d[i]=SBOX_BYTE_hi_lo(d[i]);}
static void apply_nibble_perm(uint8_t*dst,const uint8_t*src,const uint8_t*perm,size_t tot){
 uint8_t nib[64],on[64]; size_t nb=(tot+1)/2;
 for(size_t i=0;i<nb;i++){nib[2*i]=(src[i]>>4)&0xf;nib[2*i+1]=src[i]&0xf;}
 for(size_t j=0;j<tot;j++)on[j]=nib[perm[j]];
 for(size_t i=0;i<nb;i++)dst[i]=(uint8_t)((on[2*i]<<4)|on[2*i+1]);}
static void store_rk(uint32_t*rk,const uint8_t*K0,const uint8_t*K1,const uint8_t*K2,const uint8_t*K3){
 rk[0]=ld_be(K0,0);rk[1]=ld_be(K0,1);rk[2]=ld_be(K1,0);rk[3]=ld_be(K1,1);
 rk[4]=ld_be(K2,0);rk[5]=ld_be(K2,1);rk[6]=ld_be(K3,0);rk[7]=ld_be(K3,1);}
static void set_key(const uint8_t key[32],ks_t*ks){
 uint8_t K0[8],K1[8],K2[8],K3[8];
 memcpy(K0,key,8);memcpy(K1,key+8,8);memcpy(K2,key+16,8);memcpy(K3,key+24,8);
 store_rk(ks->rk[0],K0,K1,K2,K3);
 for(int i=1;i<=ROUNDS;i++){
  uint8_t tmp[16]; memcpy(tmp,K0,8);memcpy(tmp+8,K1,8);
  apply_nibble_perm(tmp,tmp,pk,32); memcpy(K0,tmp,8);memcpy(K1,tmp+8,8);
  {uint8_t t[8];uint32_t rc=RC[i-1];memcpy(t,K0,8);t[0]^=rc>>24;t[1]^=rc>>16;t[2]^=rc>>8;t[3]^=rc;apply_sn(t,8);for(int j=0;j<8;j++)K2[j]^=t[j];}
  {uint8_t t[8];memcpy(t,K1,8);apply_tk(t,8);for(int j=0;j<8;j++)K3[j]^=t[j];}
  uint8_t nK0[8],nK1[8],nK2[8],nK3[8];
  memcpy(nK0,K2,8);memcpy(nK1,K3,8);memcpy(nK2,K1,8);memcpy(nK3,K0,8);
  memcpy(K0,nK0,8);memcpy(K1,nK1,8);memcpy(K2,nK2,8);memcpy(K3,nK3,8);
  store_rk(ks->rk[i],K0,K1,K2,K3);
 }
}
static void encrypt_full(const uint8_t in[32],uint8_t out[32],const ks_t*ks){
 uint32_t X0[4],X1[4];
 for(int w=0;w<4;w++){X0[w]=ld_be(in,w);X1[w]=ld_be(in+16,w);}
 for(int i=0;i<ROUNDS;i++)round_fn(X0,X1,ks->rk[i]);
 for(int w=0;w<4;w++){st_be(X0[w]^ks->rk[ROUNDS][w],out+4*w);st_be(X1[w]^ks->rk[ROUNDS][w+4],out+16+4*w);}
}
/* DR0(x) = round1(round0(x)) under rk[0],rk[1] */
static void DR0(const uint8_t in[32],uint8_t out[32],const ks_t*ks){
 uint32_t X0[4],X1[4];
 for(int w=0;w<4;w++){X0[w]=ld_be(in,w);X1[w]=ld_be(in+16,w);}
 round_fn(X0,X1,ks->rk[0]); round_fn(X0,X1,ks->rk[1]);
 for(int w=0;w<4;w++){st_be(X0[w],out+4*w);st_be(X1[w],out+16+4*w);}
}

/* real library symbols (validate mode) */
extern int ublock256_set_key(const uint8_t*,void*);
extern void ublock256_256_encrypt(const uint8_t*,uint8_t*,const void*);

static void hexread(const char*s,uint8_t*b,int n){for(int i=0;i<n;i++){unsigned v;sscanf(s+2*i,"%2x",&v);b[i]=v;}}
static void hexprint(const uint8_t*b,int n){for(int i=0;i<n;i++)printf("%02x",b[i]);}

int main(int argc,char**argv){
 if(argc<2){fprintf(stderr,"modes: validate | kbar <pk1hex> | dr0 <pk1hex> <xhex> | fp <pk1hex> <xhex>\n");return 1;}
 if(!strcmp(argv[1],"validate")){
  /* compare our encrypt_full to real library on random inputs */
  srand(12345); int fails=0;
  for(int t=0;t<10000;t++){
   uint8_t key[32],in[32],o1[32],o2[32];
   for(int i=0;i<32;i++){key[i]=rand();in[i]=rand();}
   ks_t ks; set_key(key,&ks); encrypt_full(in,o1,&ks);
#ifdef HAVE_LIB
   /* real library ublock256_key_t is uint32_t[25][8] == our ks_t */
   ks_t rks; ublock256_set_key(key,&rks); ublock256_256_encrypt(in,o2,&rks);
   if(memcmp(o1,o2,32)){fails++; if(fails<3){printf("MISMATCH t=%d\n",t);} }
#endif
  }
#ifdef HAVE_LIB
  printf("validate: %d/10000 mismatches vs real library\n",fails);
#else
  printf("validate: self-encrypt ran (no lib linked)\n");
#endif
  return fails?2:0;
 }
 if(!strcmp(argv[1],"kbar")){
  uint8_t pk1[32]; hexread(argv[2],pk1,32); ks_t ks; set_key(pk1,&ks);
  printf("rk0="); hexprint((uint8_t*)0,0);
  uint8_t rk0[32],rk1[32];
  for(int w=0;w<8;w++){st_be(ks.rk[0][w],rk0+4*w);st_be(ks.rk[1][w],rk1+4*w);}
  printf("rk0="); hexprint(rk0,32); printf("\nrk1="); hexprint(rk1,32); printf("\n");
  return 0;
 }
 if(!strcmp(argv[1],"dr0")){
  uint8_t pk1[32],x[32],y[32]; hexread(argv[2],pk1,32); hexread(argv[3],x,32);
  ks_t ks; set_key(pk1,&ks); DR0(x,y,&ks); hexprint(y,32); printf("\n"); return 0;
 }
 if(!strcmp(argv[1],"fp")){
  uint8_t pk1[32],x[32],y[32]; hexread(argv[2],pk1,32); hexread(argv[3],x,32);
  ks_t ks; set_key(pk1,&ks); DR0(x,y,&ks);
  printf("DR0(x)="); hexprint(y,32); printf("\nx     ="); hexprint(x,32);
  printf("\nfixed_point=%s\n", memcmp(x,y,32)==0?"YES":"NO"); return 0;
 }

 if(!strcmp(argv[1],"dr0k")){ /* explicit round keys: dr0k <rk0hex64> <rk1hex64> <xhex> */
  uint8_t r0[32],r1[32],x[32],y[32]; hexread(argv[2],r0,32); hexread(argv[3],r1,32); hexread(argv[4],x,32);
  ks_t ks; memset(&ks,0,sizeof ks);
  for(int w=0;w<8;w++){ks.rk[0][w]=ld_be(r0,w);ks.rk[1][w]=ld_be(r1,w);}
  DR0(x,y,&ks); printf("DR0(x)="); hexprint(y,32); printf("\nfixed_point=%s\n",memcmp(x,y,32)==0?"YES":"NO"); return 0;
 }
 if(!strcmp(argv[1],"bench")){ /* time DR0 evaluations */
  uint8_t x[32]={1}; ks_t ks; uint8_t k[32]={2}; set_key(k,&ks); long N=20000000; uint8_t y[32];
  for(long i=0;i<N;i++){DR0(x,y,&ks); x[i&31]^=y[(i>>5)&31];}
  printf("%02x N=%ld\n",x[0],N); return 0;
 }
 return 1;
}
