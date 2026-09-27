/* Calls the unmodified reference sig_verify (linked from the reference object file). */
#include <stdio.h>
#include <stdlib.h>
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
DRNG_ctx drng_algorithm;
static unsigned char *readf(const char *fn, long *len){FILE*f=fopen(fn,"rb");if(!f){perror(fn);exit(9);}fseek(f,0,2);*len=ftell(f);rewind(f);unsigned char*b=malloc(*len+1);if(fread(b,1,*len,f)!=(size_t)*len)exit(9);fclose(f);return b;}
int main(int argc,char**argv){ long pl,sl,ml; unsigned char*pk=readf(argv[1],&pl),*m=readf(argv[2],&ml),*sn=readf(argv[3],&sl);
  int rc=sig_verify(pk,pl,sn,sl,m,ml); printf("%s\n", rc==0?"ACCEPT":"REJECT"); return rc==0?0:1;}
