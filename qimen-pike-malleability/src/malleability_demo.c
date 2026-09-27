/* Demo (local analysis, not part of submission):
   (1) non-canonical ciphertext encodings decapsulate to the SAME shared secret;
   (2) malformed ciphertexts crash kem_dec.  Each trial runs in a forked child. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "drng.h"
#include "KEM_AlgorithmInstance.h"
#include <fp.h>
#include <encoded_sizes.h>
DRNG_ctx drng_algorithm;
int main(int argc, char**argv){
  setvbuf(stdout,NULL,_IONBF,0);
  int step = argc>1? atoi(argv[1]) : 1;
  unsigned char seed[64]; for (int i=0;i<64;i++) seed[i]=(unsigned char)(i*37+11);
  init_random_number(&drng_algorithm, seed, sizeof(seed));
  unsigned long long pkl=kem_get_pk_len_bytes(), skl=kem_get_sk_len_bytes(), ctl=kem_get_ct_len_bytes(), ssl=kem_get_ss_len_bytes();
  unsigned char *pk=malloc(pkl),*sk=malloc(skl),*ct=malloc(ctl),*ct2=malloc(ctl),ss[64],ss1[64],ss2[64];
  unsigned long long a,b,c,d;
  kem_keygen(pk,&a,sk,&b); kem_enc(pk,a,ss,&d,ct,&c);
  int r0 = kem_dec(sk,b,ct,c,ss1,&d);
  printf("ALG=%s pk=%llu ct=%llu honest decaps ret=%d match=%d\n", ALGORITHM_INSTANCE, pkl, ctl, r0, !memcmp(ss,ss1,ssl));

  /* (3) add p to each Fp slot of the ciphertext (non-canonical but same field element) */
  { fp_t m1; unsigned char pb[FP_ENCODED_BYTES]; memset(pb,0,sizeof pb); fp_set_one(&m1); fp_neg(&m1,&m1); fp_encode(pb,&m1);
    int carry=1; for(int k=0;k<FP_ENCODED_BYTES;k++){ int s=pb[k]+carry; pb[k]=s&0xff; carry=s>>8; } /* pb = p (LE) */
    int same3=0, tried3=0;
    for (int slot=0; slot<8; slot++){
      memcpy(ct2,ct,ctl); unsigned char *x=ct2+slot*FP_ENCODED_BYTES; int cy=0;
      for(int k=0;k<FP_ENCODED_BYTES;k++){ int s=x[k]+pb[k]+cy; x[k]=s&0xff; cy=s>>8; }
      if (cy) continue; tried3++;
      pid_t p=fork();
      if(p==0){ int r=kem_dec(sk,b,ct2,c,ss2,&d); _exit((r==0 && !memcmp(ss,ss2,ssl) && memcmp(ct,ct2,ctl)) ? 42 : 7); }
      int st; waitpid(p,&st,0);
      if (WIFEXITED(st) && WEXITSTATUS(st)==42) same3++;
    }
    printf("add-p to Fp slot: %d/%d non-canonical ciphertexts accepted with SAME shared secret\n", same3, tried3);
  }
  if (step==0) return 0;
  int same=0, crash=0, rej=0, tried=0;
  for (unsigned long long i=0;i<ctl;i+=step){
    memcpy(ct2,ct,ctl); ct2[i]^=0x80; tried++;
    pid_t p=fork();
    if(p==0){ int r=kem_dec(sk,b,ct2,c,ss2,&d); _exit((r==0 && !memcmp(ss,ss2,ssl)) ? 42 : 7); }
    int st; waitpid(p,&st,0);
    if (WIFSIGNALED(st)) { crash++; printf("offset %llu: CRASH signal %d\n", i, WTERMSIG(st)); }
    else if (WEXITSTATUS(st)==42) { same++; printf("offset %llu: accepted, SAME shared secret\n", i); }
    else rej++;
  }
  printf("summary: tried=%d same_key_accepted=%d crashed=%d rejected=%d\n", tried, same, crash, rej);
  return 0;
}
