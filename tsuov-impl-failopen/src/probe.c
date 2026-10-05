/* TSUOV round-5 probe: encoding/length/interop. Writes keys+sigs to files for cross-impl checks. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
DRNG_ctx drng_algorithm;
static int getel(const unsigned char*s,size_t bit){size_t i=bit>>3;int sh=bit&7;int x=s[i]|((sh+5>8)?s[i+1]<<8:0);return (x>>sh)&31;}
static void setel(unsigned char*s,size_t bit,int v){size_t i=bit>>3;int sh=bit&7;int x=s[i]|((sh+5>8)?(s[i+1]<<8):0);x&=~(31<<sh);x|=v<<sh;s[i]=x&255;if(sh+5>8)s[i+1]=(x>>8)&255;}
static void dump(const char*fn,const unsigned char*b,size_t n){FILE*f=fopen(fn,"wb");fwrite(b,1,n,f);fclose(f);}
static size_t slurp(const char*fn,unsigned char*b,size_t n){FILE*f=fopen(fn,"rb");if(!f)return 0;size_t r=fread(b,1,n,f);fclose(f);return r;}
int main(int argc,char**argv){
  size_t PL=sig_get_pk_len_bytes(),SL=sig_get_sk_len_bytes(),NL=sig_get_sn_len_bytes();
  unsigned char *pk=calloc(PL+64,1),*sk=calloc(SL+64,1),*sn=calloc(NL+64,1),*sn2=calloc(NL+64,1),*pk2=calloc(PL+64,1);
  unsigned char m[64]; for(int i=0;i<64;i++)m[i]=i;
  unsigned long long pl=PL,sl,snl=NL;
  const char*tag=argc>2?argv[2]:"x";
  if(argc>1 && !strcmp(argv[1],"verify")){ /* cross-impl: verify files produced by the other tree */
    char fn[256]; int acc=0,tot=0;
    for(int t=0;t<8;t++){ sprintf(fn,"%s_pk%d.bin",tag,t); if(!slurp(fn,pk,PL))break; sprintf(fn,"%s_sn%d.bin",tag,t); slurp(fn,sn,NL);
      m[0]=t; tot++; if(sig_verify(pk,PL,sn,NL,m,64)==0)acc++; }
    printf("%s cross-verify %s: honest %d/%d\n",ALGORITHM_INSTANCE,tag,acc,tot);
    acc=0;tot=0;
    for(int t=0;t<8;t++){ sprintf(fn,"%s_pknc%d.bin",tag,t); if(!slurp(fn,pk,PL))break; sprintf(fn,"%s_snnc%d.bin",tag,t); slurp(fn,sn,NL);
      m[0]=t; tot++; if(sig_verify(pk,PL,sn,NL,m,64)==0)acc++; }
    printf("%s cross-verify %s: non-canonical (all-zeros->31 in sig AND pk) %d/%d accepted\n",ALGORITHM_INSTANCE,tag,acc,tot);
    return 0; }
  unsigned char seed[64]; for(int i=0;i<64;i++)seed[i]=i*13+5;
  init_random_number(&drng_algorithm, seed, 64);
  size_t sbase=SIG_SALT_BITS, nsel=(NL*8-sbase)/5;
  size_t pbase=PK_SEED_BITS,  npel=(PL*8-pbase)/5; size_t padbits=PL*8-pbase-5*npel;
  printf("%s pk=%zu sig=%zu sig_elems=%zu pk_elems=%zu pk_pad_bits=%zu\n",ALGORITHM_INSTANCE,PL,NL,nsel,npel,padbits);
  int A[8]={0};
  for(int t=0;t<8;t++){
    sig_keygen(pk,&pl,sk,&sl); m[0]=t; sig_sign(sk,sl,m,64,sn,&snl);
    char fn[256]; sprintf(fn,"%s_pk%d.bin",tag,t); dump(fn,pk,PL); sprintf(fn,"%s_sn%d.bin",tag,t); dump(fn,sn,NL);
    A[0]+= sig_verify(pk,pl,sn,snl,m,64)==0;
    /* (1) sig: every zero coordinate -> 31 simultaneously */
    memcpy(sn2,sn,NL); int z=0; for(size_t e=0;e<nsel;e++) if(getel(sn,sbase+5*e)==0){setel(sn2,sbase+5*e,31);z++;}
    int r1=sig_verify(pk,pl,sn2,snl,m,64)==0; A[1]+=r1;
    /* (2) pk: every zero coordinate of P3 -> 31 */
    memcpy(pk2,pk,PL); int zp=0; for(size_t e=0;e<npel;e++) if(getel(pk,pbase+5*e)==0){setel(pk2,pbase+5*e,31);zp++;}
    int r2=sig_verify(pk2,pl,sn,snl,m,64)==0; A[2]+=r2;
    int r2b=sig_verify(pk2,pl,sn2,snl,m,64)==0;
    sprintf(fn,"%s_pknc%d.bin",tag,t); dump(fn,pk2,PL); sprintf(fn,"%s_snnc%d.bin",tag,t); dump(fn,sn2,NL);
    /* (3) pk padding bits */
    int r3=-1; if(padbits){ memcpy(pk2,pk,PL); pk2[PL-1]^=(unsigned char)(0xFF<<(8-padbits)); r3=sig_verify(pk2,pl,sn,snl,m,64)==0; A[3]+=r3; }
    /* (4) trailing junk after signature, declared length NL+16 */
    memcpy(sn2,sn,NL); memset(sn2+NL,0xA5,16); int r4=sig_verify(pk,pl,sn2,NL+16,m,64)==0; A[4]+=r4;
    /* (5) declared length shorter than NL (buffer still holds full sig) */
    int r5=sig_verify(pk,pl,sn,NL-1,m,64)==0; A[5]+=r5;
    int r6=sig_verify(pk,1,sn,snl,m,64)==0; A[6]+=r6;  /* declared pk_len=1 */
    printf(" t=%d sig zeros=%d ->31 %s | pk zeros=%d ->31 %s | both %s | pkpad %s | sn_len+16 %s | sn_len-1 %s | pk_len=1 %s\n",
      t,z,r1?"ACCEPT":"rej",zp,r2?"ACCEPT":"rej",r2b?"ACCEPT":"rej",r3<0?"n/a":(r3?"ACCEPT":"rej"),r4?"ACCEPT":"rej",r5?"ACCEPT":"rej",r6?"ACCEPT":"rej");
  }
  printf("SUMMARY %s honest %d/8 sigNC %d/8 pkNC %d/8 pkpad %d/8 trailing %d/8 short %d/8 pklen1 %d/8\n",ALGORITHM_INSTANCE,A[0],A[1],A[2],A[3],A[4],A[5],A[6]);
  return 0;
}
