/* Finding 3 (support): the decapsulation success/failure bit is observable by an UNAUTHENTICATED
 * responder. In pMAKE-BW, A completes round 3 (sends c_seed^A) whenever its decapsulation of ct_A
 * succeeds, before authenticating the peer. A responder M with an uncertified key can therefore learn,
 * per session, whether a ciphertext of its choice decapsulated under cpk_A. This is the oracle that
 * the spec's Sec 2.7/3.2 DFA-resilience argument assumes away.
 *
 * We inject a decapsulation failure by flipping one ciphertext byte (a stand-in for a genuine
 * decryption failure) and check that the responder's seed reconstruction succeeds iff A decapsulated
 * the SAME K_A. Mode 0: honest ct_A (A succeeds). Mode 1: corrupted ct_A (A gets a different K_A).
 * No secret key is read by M; M uses only its own composite key.
 */
#include "common.h"
static struct { const char *id; unsigned char pk[PK]; } CA[8]; static int nca;
static void ca_reg(const char *id,const unsigned char*pk){ CA[nca].id=id; memcpy(CA[nca].pk,pk,PK); nca++; }
static int CAVerf(const char*id,const unsigned char*pk){ for(int i=0;i<nca;i++) if(!strcmp(CA[i].id,id)) return !memcmp(CA[i].pk,pk,PK); return 0; }
int main(int argc,char**argv){
  int TR=argc>1?atoi(argv[1]):200; int agree[2]={0,0};
  party A,M; keygen(&A); keygen(&M); ca_reg("alice",A.pk); /* M is NOT registered */
  for(int mode=0;mode<2;mode++) for(int t=0;t<TR;t++){
    unsigned char seedA[L],cpkA[PK],cskA[SK],sM[L],cpkM[PK],cskM[SK];
    unsigned char ctA[CT],KA[L],KAp[L],ctB[CT],KB[L],KBp[L],outA[3*L],outM[3*L],cA[L],s[L],pkx[PK];
    rnd(seedA,L); composite(&A,seedA,cpkA,cskA);
    rnd(sM,L);    composite(&M,sM,cpkM,cskM); enc(ctA,KA,cpkA);
    if(mode) ctA[t%CT]^=1;                                   /* injected failure */
    crypto_kem_dec(KAp,ctA,cskA); enc(ctB,KB,cpkM); prf(KAp,KB,outA);
    xorL(cA,outA+L,seedA);                                    /* A -> M (M not yet authenticated) */
    crypto_kem_dec(KBp,ctB,cskM); prf(KA,KBp,outM);
    xorL(s,cA,outM+L); extract(cpkA,s,pkx);
    agree[mode]+=CAVerf("alice",pkx);                         /* M's seed check passes iff A's decap == KA */
  }
  printf("[ORACLE] level=%s trials=%d\n", AFSLEVEL, TR);
  printf("[ORACLE] unauthenticated M sees A-decap-success: honest=%d/%d  injected-failure=%d/%d\n",
         agree[0],TR,agree[1],TR);
  int pass = agree[0]==TR && agree[1]==0;
  printf("[ORACLE] RESULT: %s (a per-session failure oracle open to an unauthenticated peer)\n",
         pass?"CONFIRMED":"NOT REPRODUCED");
  return pass?0:1;
}
