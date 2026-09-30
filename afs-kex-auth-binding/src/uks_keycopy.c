/* Finding 2: identities are not bound into K_SESSION (unknown-key-share by public-key copy).
 *
 * K_SESSION = PRF(K_A, K_B); id_A, id_B travel in the clear and enter no KDF/MAC. An adversary E
 * registers a copy of pk_A under id_E, relays an A<->B session, and rewrites id_A -> id_E in the
 * round-3 message. Then B accepts with peer=E, A accepts with peer=B, and both hold the SAME key.
 * The model (Sec 8.2 Setup) has the challenger generate all static keys, so this is outside it; a
 * real PKI cannot force a signature-style proof of possession for KEM keys (see README).
 * No secret key of A is used: E only re-registers A's PUBLIC key.
 */
#include "common.h"
static struct { const char *id; unsigned char pk[PK]; } CA[8]; static int nca;
static void ca_reg(const char *id,const unsigned char*pk){ CA[nca].id=id; memcpy(CA[nca].pk,pk,PK); nca++; }
static int CAVerf(const char*id,const unsigned char*pk){ for(int i=0;i<nca;i++) if(!strcmp(CA[i].id,id)) return !memcmp(CA[i].pk,pk,PK); return 0; }
int main(int argc,char**argv){
  int TR=argc>1?atoi(argv[1]):200, ok_uks=0;
  for(int t=0;t<TR;t++){
    party A,B; keygen(&A); keygen(&B);
    nca=0; ca_reg("alice",A.pk); ca_reg("bob",B.pk); ca_reg("eve",A.pk); /* Eve = copy of Alice's PUBLIC key */
    unsigned char seedA[L],cpkA[PK],cskA[SK],seedB[L],cpkB[PK],cskB[SK];
    unsigned char ctA[CT],KA[L],KAp[L],ctB[CT],KB[L],KBp[L],outA[3*L],outB[3*L],cA[L],cB[L],s[L],pkx[PK];
    rnd(seedA,L); composite(&A,seedA,cpkA,cskA);                  /* R1 A->: cpkA (relayed unchanged) */
    rnd(seedB,L); composite(&B,seedB,cpkB,cskB); enc(ctA,KA,cpkA);/* R2 B->: cpkB, ctA */
    crypto_kem_dec(KAp,ctA,cskA); enc(ctB,KB,cpkB); prf(KAp,KB,outA);
    xorL(cA,outA+L,seedA);                                        /* R3 A->: id_A rewritten to "eve" */
    const char *idA_wire="eve";
    crypto_kem_dec(KBp,ctB,cskB); prf(KA,KBp,outB);
    xorL(s,cA,outB+L); extract(cpkA,s,pkx);
    int b_ok=CAVerf(idA_wire,pkx);                                /* B verifies "eve" -> pk_A: passes */
    xorL(cB,outB+2*L,seedB);                                      /* R4 B->: ("bob",cB) */
    xorL(s,cB,outA+2*L); extract(cpkB,s,pkx);
    int a_ok=CAVerf("bob",pkx);
    ok_uks += (a_ok && b_ok && !memcmp(outA,outB,L));
  }
  printf("[UKS] level=%s trials=%d\n", AFSLEVEL, TR);
  printf("[UKS] A believes peer=bob, B believes peer=eve, keys equal: %d/%d\n", ok_uks, TR);
  printf("[UKS] RESULT: %s\n", ok_uks==TR?"CONFIRMED":"NOT REPRODUCED");
  return ok_uks==TR?0:1;
}
