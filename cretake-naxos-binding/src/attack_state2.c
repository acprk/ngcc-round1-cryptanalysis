/* CreTAKE S2K/S2S: initiator StateReveal alone (no long-term key) recovers session key,
 * because G(sk_i, r) is implemented as pseudohash(.., r||sk_i, (SEED_BYTES+SKI_LEN) BITS)
 * which absorbs only r and a prefix of sk_i that coincides with the PUBLIC key. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KEX_AlgorithmInstance.h"
#include "drng.h"
#include "cretake_params.h"
DRNG_ctx drng_algorithm;
int main(int argc, char **argv){
  int trials = argc > 1 ? atoi(argv[1]) : 20;
  unsigned long long pl = kex_get_pk_len_bytes(), sl = kex_get_sk_len_bytes(),
    stal = kex_get_sta_len_bytes(), stbl = kex_get_stb_len_bytes(), ssl = kex_get_ss_len_bytes(),
    tot = kex_get_total_msg_len_bytes();
  unsigned char *pka=calloc(pl,1),*ska=calloc(sl,1),*pkb=calloc(pl,1),*skb=calloc(sl,1),
    *sta=calloc(stal+64,1),*stb=calloc(stbl+64,1),*stcopy=calloc(stal+64,1),*m1=calloc(tot,1),*m2=calloc(tot,1),
    *ssa=calloc(ssl,1),*ssb=calloc(ssl,1),*ssx=calloc(ssl,1),*fake=calloc(sl,1);
  unsigned long long a,b,c,d,e,f,g,h,i2,j;
  unsigned char seed[64]; FILE *ur=fopen("/dev/urandom","rb"); fread(seed,1,64,ur); fclose(ur);
  init_random_number(&drng_algorithm, seed, 64);
  unsigned long long absorbed = (SEED_BYTES + SKI_LEN)/8;  /* bytes actually hashed */
  long long skbytes_abs = (long long)absorbed - SEED_BYTES;
  int ok=0, honest=0, pkprefix=1;
  for(int t=0;t<trials;t++){
    kex_init_a(pka,&a,ska,&b,sta,&c); kex_init_b(pkb,&d,skb,&e,stb,&f);
    if (memcmp(ska, pka, skbytes_abs) != 0) pkprefix = 0;     /* absorbed sk prefix == public pk? */
    if (kex_generate_pass1_msg_a(ska,b,pkb,d,sta,&c,m1,&g)!=0){printf("pass1 fail\n");return 1;}
    memcpy(stcopy, sta, c);                     /* StateReveal(initiator session) */
    unsigned long long stlen=c;
    if (kex_generate_pass2_msg_b(skb,e,pka,a,m1,g,stb,&f,m2,&h)<0){printf("pass2 fail\n");return 1;}
    if (kex_derive_ss_a(ska,b,pkb,d,m2,h,sta,c,ssa,&i2)!=0){printf("derive_a fail\n");return 1;}
    kex_derive_ss_b(skb,e,pka,a,m1,g,stb,f,ssb,&j);
    if (i2==j && !memcmp(ssa,ssb,i2)) honest++;
    /* attacker: knows only pka (public), pkb, m1, m2 and revealed state. Fake sk = pk || zeros */
    for(unsigned long long q=0;q<sl;q++)fake[q]=(unsigned char)rand(); memcpy(fake,pka,PKI_LEN); /* only public pk; bytes beyond PKI_LEN stay random */
    if (kex_derive_ss_a(fake,b,pkb,d,m2,h,stcopy,stlen,ssx,&i2)==0 && !memcmp(ssx,ssa,ssl)) ok++;
  }
  printf("%s: SEED_BYTES=%d SKI_LEN=%d PKI_LEN=%d absorbed_bytes=%llu (r=%d + sk_prefix=%lld) sk_prefix_is_public=%s\n",
    ALGORITHM_INSTANCE, SEED_BYTES, SKI_LEN, PKI_LEN, absorbed, SEED_BYTES, skbytes_abs, pkprefix?"yes":"NO");
  printf("RESULT %s honest_match=%d/%d staterev_key_recovered=%d/%d (attacker sk = pk||0)\n", ALGORITHM_INSTANCE, honest, trials, ok, trials);
  printf("ss[0..8]=%02x%02x%02x%02x%02x%02x%02x%02x\n",ssa[0],ssa[1],ssa[2],ssa[3],ssa[4],ssa[5],ssa[6],ssa[7]);
  return 0;
}
