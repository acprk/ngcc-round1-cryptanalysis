/* Direct refutation of the authors' 2026-09-22 forum reply (message .../M4U5QIFR.../):
 *   "to impersonate Alice, compromising only the encapsulated key ss does not work, as the
 *    successful AFS-KEM based authentication also needs the knowledge of ephemeral secret key
 *    seed that is however held by Alice herself."
 *
 * Claim under test: impersonating Alice needs seed, which only Alice holds.
 * Result: FALSE. To impersonate Alice to Bob the attacker needs ONLY
 *   (a) Alice's public key pk_A (public), and
 *   (b) a leak of the in-session encapsulated secret K_A that Bob (responder) computes
 *       -- i.e. exactly the "encapsulated key ss" of the authors' scenario (2).
 * The attacker CHOOSES its own seed*; nothing is held by Alice, nothing is harvested, and no
 * secret of Alice is used. Alice never participates in this session at all.
 *
 * Why the CAVerf check is not a barrier: cpk_A is authenticated by extracting
 *   pk'_A = cpk_A - t_e(seed)  and testing CAVerf(id_A, pk'_A).
 * Anyone who knows pk_A can set cpk* = pk_A + t_e(seed*) for a self-chosen seed*, so the
 * extracted pk'_A equals pk_A and CAVerf passes. The only thing that binds the SESSION KEY to
 * Alice is K_A = Decaps(csk_A, ct_A), which needs csk_A = s_A + s_e -> Alice's STATIC secret
 * s_A, NOT seed. So the authenticating secret is s_A, and leaking K_A (the ss) bypasses it.
 *
 * PURITY: the attacker path reads no secret key. pk_A is public; K_A is the injected "leak"
 * (the authors' ss). Control run without the K_A leak must be rejected.
 */
#include "common.h"
static struct { const char *id; unsigned char pk[PK]; } CA[8]; static int nca;
static void ca_reg(const char *id,const unsigned char*pk){ CA[nca].id=id; memcpy(CA[nca].pk,pk,PK); nca++; }
static int CAVerf(const char*id,const unsigned char*pk){ for(int i=0;i<nca;i++) if(!strcmp(CA[i].id,id)) return !memcmp(CA[i].pk,pk,PK); return 0; }
/* attacker-side: composite public key from Alice's PUBLIC key alone, chosen seed. No secret. */
static void composite_pub(const unsigned char *pkA, const unsigned char seed[L], unsigned char *cpk){
  unsigned char pke[KYBER_INDCPA_PUBLICKEYBYTES], ske[KYBER_INDCPA_SECRETKEYBYTES]; polyvec a,b,c;
  indcpa_keypair_ekeygen(pkA,seed,pke,ske);            /* uses only pk' (public) */
  polyvec_frombytes(&a,pkA); polyvec_frombytes(&b,pke); polyvec_add(&c,&a,&b); polyvec_reduce(&c);
  polyvec_tobytes(cpk,&c); memcpy(cpk+KYBER_POLYVECBYTES,pkA+KYBER_POLYVECBYTES,L);
}
int main(int argc,char**argv){
  int TR=argc>1?atoi(argv[1]):200, accept=0, keymatch=0, ctrl=0, used_seed_of_alice=0;
  party A; keygen(&A); ca_reg("alice",A.pk);           /* Alice exists only as a certified pk_A */
  for(int t=0;t<TR;t++){
    for(int leak=1; leak>=0; leak--){
      party B; keygen(&B);
      unsigned char seedStar[L],cpkStar[PK], seedB[L],cpkB[PK],cskB[SK];
      unsigned char ctA[CT],KA[L], ctB[CT],KBe[L], o[3*L], cA[L], KBp[L], oB[3*L], s[L], pkx[PK], KAuse[L];
      /* R1  E->B : cpk* built from pk_A + attacker-chosen seed* (no secret, no harvest) */
      rnd(seedStar,L); composite_pub(A.pk,seedStar,cpkStar);
      /* R2  B->E : (cpk_B, ct_A);  B computes K_A internally */
      rnd(seedB,L); composite(&B,seedB,cpkB,cskB);
      enc(ctA,KA,cpkStar);                              /* this is Bob's in-session ss = K_A */
      if(leak) memcpy(KAuse,KA,L); else rnd(KAuse,L);   /* (b): leak of K_A, or control */
      /* R3  E->B : (id_A, ct_B, c_seed^A) */
      enc(ctB,KBe,cpkB);                                /* E encapsulates -> knows K_B */
      prf(KAuse,KBe,o);
      xorL(cA,o+L,seedStar);                            /* c_seed^A = K_ENC^A xor seed* */
      /* R4  B verifies */
      crypto_kem_dec(KBp,ctB,cskB); prf(KA,KBp,oB);
      xorL(s,cA,oB+L); extract(cpkStar,s,pkx);          /* B extracts pk'_A */
      int ok = CAVerf("alice",pkx);                     /* passes: pk'_A == pk_A */
      int km = ok && !memcmp(o,oB,L);                   /* E's key == B's key */
      if(leak){ accept+=ok; keymatch+=km; used_seed_of_alice+=0; } else ctrl+=ok;
    }
  }
  printf("[REPLY3] level=%s trials=%d  (attacker inputs: pk_A [public] + leaked K_A; seed chosen by attacker)\n", AFSLEVEL, TR);
  printf("[REPLY3] Bob accepts peer=alice (K_A leaked)      : %d/%d\n", accept, TR);
  printf("[REPLY3]   ... and attacker key == Bob's key      : %d/%d\n", keymatch, TR);
  printf("[REPLY3] Bob accepts peer=alice (control,no leak) : %d/%d (must be 0)\n", ctrl, TR);
  printf("[REPLY3] any secret of Alice used                 : no (seed is attacker-chosen)\n");
  int pass = accept==TR && keymatch==TR && ctrl==0;
  printf("[REPLY3] RESULT: %s -- the forum claim (\"also needs the seed held by Alice\") is refuted\n", pass?"CONFIRMED":"NOT REPRODUCED");
  return pass?0:1;
}
