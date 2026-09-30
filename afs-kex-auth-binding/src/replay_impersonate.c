/* Finding 1: the initiator's credential (cpk_A, seed_A) is replayable.
 *
 * pMAKE-BW (spec Fig. 3). A sends c_seed^A = K_ENC^A xor seed_A in round 3, BEFORE it has
 * authenticated the responder. Any responder (registered or not) knows K_A (it encapsulated
 * to cpk_A) and K_B (it decapsulates ct_B under its own composite key), so it recovers seed_A.
 * (cpk_A, seed_A) is session-independent: cpk_A is sent in round 1, before any responder input.
 *
 * Attack: an attacker who once played responder to A holds (cpk_A^old, seed_A^old). Later, if a
 * responder's in-session encapsulated key K_A leaks, the attacker replays cpk_A^old to Bob and,
 * using the leaked K_A, completes round 3 so that Bob accepts peer = Alice and the attacker knows
 * K_SESSION. Uses NO secret of Alice. Control run (no leak) must be rejected.
 *
 * SCORING NOTE: no secret key of any honest party is read by the attacker code path. The only
 * "leak" injected is a per-session public-computation value K_A, which the spec's model (Sec 9.1)
 * assumes erased; see README. TRIALS default 200.
 */
#include "common.h"
static struct { const char *id; unsigned char pk[PK]; } CA[8]; static int nca;
static void ca_reg(const char *id,const unsigned char*pk){ CA[nca].id=id; memcpy(CA[nca].pk,pk,PK); nca++; }
static int CAVerf(const char*id,const unsigned char*pk){ for(int i=0;i<nca;i++) if(!strcmp(CA[i].id,id)) return !memcmp(CA[i].pk,pk,PK); return 0; }
int main(int argc,char**argv){
  int TR = argc>1?atoi(argv[1]):200;
  party A,E; keygen(&A); keygen(&E); ca_reg("alice",A.pk); ca_reg("eve",E.pk);
  int harvest_ok=0, leak_accept=0, leak_keymatch=0, ctrl_accept=0;
  unsigned char cpkOld[PK], seedOld[L];  int have_old=0;
  for(int t=0;t<TR;t++){
    /* ---- Phase 1: Alice initiates toward Eve (an ordinary, honestly registered responder) ---- */
    unsigned char seedA[L],cpkA[PK],cskA[SK],sE[L],cpkE[PK],cskE[SK];
    unsigned char ctA[CT],KA[L],KAp[L],ctB[CT],KB[L],KBp[L],outA[3*L],outE[3*L],cA[L],seedRec[L];
    rnd(seedA,L); composite(&A,seedA,cpkA,cskA);                 /* R1 A->: cpkA */
    rnd(sE,L);    composite(&E,sE,cpkE,cskE); enc(ctA,KA,cpkA);   /* R2 E->: cpkE, ctA */
    crypto_kem_dec(KAp,ctA,cskA); enc(ctB,KB,cpkE); prf(KAp,KB,outA);
    xorL(cA,outA+L,seedA);                                        /* R3 A->: ("alice",ctB,cA) */
    crypto_kem_dec(KBp,ctB,cskE); prf(KA,KBp,outE);              /* Eve recovers seed_A */
    xorL(seedRec,cA,outE+L);
    harvest_ok += !memcmp(seedRec,seedA,L);
    if(!have_old){ memcpy(cpkOld,cpkA,PK); memcpy(seedOld,seedRec,L); have_old=1; }
    /* ---- Phase 2: replay cpkOld to Bob; two runs: leaked K_A vs control ---- */
    for(int leak=1; leak>=0; leak--){
      party B; keygen(&B); ca_reg("bob",B.pk); nca--;            /* fresh Bob each trial */
      unsigned char seedB[L],cpkB[PK],cskB[SK],ctA2[CT],KA2[L],KAuse[L],ctB2[CT],KBe[L],o[3*L],cA2[L],s[L],pkx[PK],oB[3*L];
      rnd(seedB,L); composite(&B,seedB,cpkB,cskB);               /* Bob R1->R2 with replayed cpkOld */
      enc(ctA2,KA2,cpkOld);                                       /* Bob encapsulates to cpkOld -> K_A2 */
      if(leak) memcpy(KAuse,KA2,L); else rnd(KAuse,L);            /* leak of Bob's in-session K_A (or not) */
      enc(ctB2,KBe,cpkB); prf(KAuse,KBe,o);
      xorL(cA2,o+L,seedOld);                                      /* Eve->Bob: ("alice",ctB2,cA2) */
      crypto_kem_dec(KBp,ctB2,cskB); prf(KA2,KBp,oB);            /* Bob's view */
      xorL(s,cA2,oB+L); extract(cpkOld,s,pkx);
      int ok=CAVerf("alice",pkx);
      int km = ok && !memcmp(o,oB,L);
      if(leak){ leak_accept+=ok; leak_keymatch+=km; } else ctrl_accept+=ok;
    }
  }
  printf("[REPLAY] level=%s trials=%d\n", AFSLEVEL, TR);
  printf("[REPLAY] seed_A harvested by responder : %d/%d\n", harvest_ok, TR);
  printf("[REPLAY] Bob accepts peer=alice (K_A leaked)   : %d/%d\n", leak_accept, TR);
  printf("[REPLAY]   ... and attacker key == Bob's key   : %d/%d\n", leak_keymatch, TR);
  printf("[REPLAY] Bob accepts peer=alice (control,no leak): %d/%d (must be 0)\n", ctrl_accept, TR);
  int pass = harvest_ok==TR && leak_keymatch==TR && ctrl_accept==0;
  printf("[REPLAY] RESULT: %s\n", pass?"CONFIRMED":"NOT REPRODUCED");
  return pass?0:1;
}
