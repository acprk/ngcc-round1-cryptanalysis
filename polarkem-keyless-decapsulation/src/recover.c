/* Polar-KEM: recover shared secret from (pk, ct) only — no secret key used. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "polarkem_params.h"
#include "polarkem_ct.h"
static int hex2bin(const char *h, unsigned char *o, size_t n){for(size_t i=0;i<n;i++){unsigned v; if(sscanf(h+2*i,"%2x",&v)!=1)return -1;o[i]=(unsigned char)v;}return 0;}
int main(int argc,char**argv){
  FILE*f=fopen(argv[1],"r"); char *line=NULL; size_t cap=0; ssize_t r;
  unsigned char pk[POLARKEM_PK_BYTES], ct[POLARKEM_CT_BYTES], ss[POLARKEM_SS_BYTES], mu[POLARKEM_MESSAGE_BYTES], ss2[POLARKEM_SS_BYTES];
  int ok=0,tot=0;
  while((r=getline(&line,&cap,f))>0){
    if(!strncmp(line,"PK = ",5)) hex2bin(line+5,pk,POLARKEM_PK_BYTES);
    else if(!strncmp(line,"CT = ",5)) hex2bin(line+5,ct,POLARKEM_CT_BYTES);
    else if(!strncmp(line,"SS = ",5)){ hex2bin(line+5,ss,POLARKEM_SS_BYTES);
      polarkem_recover_message(pk,ct,mu); polarkem_derive_valid_secret(mu,ct,ss2);
      tot++; if(!memcmp(ss,ss2,POLARKEM_SS_BYTES)) ok++; }
  }
  printf("%s: recovered SS from pk+ct only in %d/%d KAT records\n",argv[1],ok,tot); return 0;}
