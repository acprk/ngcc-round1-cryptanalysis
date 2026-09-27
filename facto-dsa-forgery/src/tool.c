/* Harness: #includes the UNMODIFIED reference SIG_AlgorithmInstance.c to reuse keygen and the
   hash-to-field (xof_field). Only public data (pk, msg) is used for 'hash'. */
#include "SIG_AlgorithmInstance.c"
DRNG_ctx drng_algorithm;
static unsigned char *readf(const char *fn, long *len){FILE*f=fopen(fn,"rb");if(!f){perror(fn);exit(1);}fseek(f,0,2);*len=ftell(f);rewind(f);unsigned char*b=malloc(*len+1);if(fread(b,1,*len,f)!=(size_t)*len)exit(1);fclose(f);return b;}
static void writef(const char*fn,const unsigned char*b,long len){FILE*f=fopen(fn,"wb");fwrite(b,1,len,f);fclose(f);}
int main(int argc,char**argv){
  if(argc<2){fprintf(stderr,"usage: keygen pk sk | hash pk msg | sign sk msg sig\n");return 1;}
  unsigned char seed[64]; if(getentropy(seed,64))return 1; init_random_number(&drng_algorithm,seed,64);
  if(!strcmp(argv[1],"keygen")){unsigned char*pk=malloc(PK_BYTES),*sk=malloc(SK_BYTES);unsigned long long pl,sl;
    int rc=sig_keygen(pk,&pl,sk,&sl); if(rc)return rc; writef(argv[2],pk,pl);writef(argv[3],sk,sl);return 0;}
  if(!strcmp(argv[1],"hash")){long pl,ml;unsigned char*pk=readf(argv[2],&pl),*m=readf(argv[3],&ml);unsigned char pkh[FACTO_PKH_BYTES];
    sm3_digest(pk,pl,pkh); fe_t h[FACTO_M]; if(xof_field(pkh,m,ml,h))return 2; for(int i=0;i<FACTO_M;i++)printf("%u ",(unsigned)h[i]);printf("\n");return 0;}
  if(!strcmp(argv[1],"sign")){long sl,ml;unsigned char*sk=readf(argv[2],&sl),*m=readf(argv[3],&ml);unsigned char sn[SN_BYTES];unsigned long long snl;
    int rc=sig_sign(sk,sl,m,ml,sn,&snl);if(rc)return 3;writef(argv[4],sn,snl);return 0;}
  return 1;}
