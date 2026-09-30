// Exp B: GENUINE, self-locating search (no oracle) -> real key recovery -> real forgery.
//
// Honest accounting of what each side knows:
//  * Public (attacker) inputs: pk, the signature, and everything derived from them (mu, s, iv, the
//    challenge decoding, the revealed BAVC nodes, the hidden-leaf commitments, c, d).
//  * Evaluator-only handicap to make the search feasible: the attacker is *given* the top lambda-B
//    bits of ONE hidden bottom-parent node and brute-forces only the low B bits. This models the
//    feasible slice of the real 2^lambda search; nothing else evaluator-side enters the attack.
//
// The search tests each guess by expanding it with the SUBMITTED TCCR and looking the child up in a
// hash table over ALL T revealed node values (the genuine multi-target test). A hit reports WHICH
// target index it matched; the entire recovery (hidden leaf -> witness -> forgery) is driven by that
// discovered index, using public data only.  Restricted to bottom parents (children are leaves), so
// one hit yields a hidden leaf directly.
#define SIG_TESTS 1
#include "bavc.c"
#include "vole.c"
#include "voleith_impl.c"
#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "rsd.h"
#include <stdio.h>
#include <stdint.h>
DRNG_ctx drng_algorithm;
#define HC 11400714819323198485ull
static int getb(const uint8_t*s,unsigned i){return (s[i>>3]>>(i&7))&1;}
static void setb(uint8_t*s,unsigned i){s[i>>3]|=(uint8_t)(1u<<(i&7));}
int main(int argc,char**argv){
  unsigned B = argc>1?(unsigned)atoi(argv[1]):24;
  unsigned char nonce[64]; for(int i=0;i<64;i++)nonce[i]=(unsigned char)(i*13+5);
  init_random_number(&drng_algorithm,nonce,64);
  const sig_paramset_t*P=sig_get_paramset(SETID);
  const unsigned lambda=P->csp,lb=lambda/8,L=P->L,tau=P->tau;
  const unsigned ehb=ell_hat_bytes(P),ell=P->lenwit,ellb=(ell+7)/8;
  unsigned long long pkl=sig_get_pk_len_bytes(),skl=sig_get_sk_len_bytes(),snl=sig_get_sn_len_bytes();

  uint8_t*pk=malloc(pkl),*sk=malloc(skl),*sig=calloc(1,snl),*sig2=calloc(1,snl);
  unsigned long long a=pkl,b=skl; sig_keygen(pk,&a,sk,&b);
  const unsigned in_sz=P->owf_input_size; const uint8_t*owf_input=sk,*owf_key=sk+in_sz;
  uint8_t witness[1024]={0}; rsd_extend_witness(witness,owf_key,owf_input,P);
  uint8_t rho[64]; get_random_number(&drng_algorithm,rho,lambda);
  uint8_t msg[32]; memset(msg,0xC1,sizeof msg);
  voleith_sign(sig,msg,sizeof msg,owf_key,owf_input,pk+in_sz,witness,rho,lb,P);
  if(sig_verify(pk,a,sig,snl,msg,sizeof msg)!=0){printf("honest reject?!\n");return 1;}

  // ===== public parsing (attacker side) =====
  uint8_t mu[2*MAX_CSP_BYTES],s[MAX_CSP_BYTES],iv[IV_SIZE];
  hash_mu_s(mu,s,pk,in_sz,pk+in_sz,P->owf_output_size,msg,sizeof msg,lambda);
  memcpy(iv,dsignature_iv(sig,P),IV_SIZE);
  uint16_t delta[MAX_TAU]; decode_all_chall_3(delta,dsignature_chall_3(sig,P),P);
  const uint8_t*decom=dsignature_decom_i(sig,P),*coms=decom,*nodes=decom+2*tau*lb;
  uint8_t*S=calloc((2*L-1+7)/8,1); unsigned hid_leaf[MAX_TAU];
  for(unsigned i=0;i<tau;i++){unsigned al=pos_in_tree(i,delta[i],P);hid_leaf[i]=al;setb(S,al);
    while(al>0&&!getb(S,(al-1)/2)){al=(al-1)/2;setb(S,al);}}
  unsigned T=0,par[8192],chi[8192];
  for(int i=(int)L-2;i>=0;--i){int l=getb(S,2*i+1),r=getb(S,2*i+2); if(l|r)setb(S,i);
    if(l^r){par[T]=(unsigned)i;chi[T]=2*i+1+l;T++;}}
  uint8_t const0[MAX_CSP_BYTES]={0},const1[MAX_CSP_BYTES]={0}; const1[0]=1;

  // real multi-target set: value(first 8 bytes) -> target index (open addressing)
  uint32_t hsz=1; while(hsz<4*T) hsz<<=1; uint32_t hmask=hsz-1;
  uint64_t*ht=calloc(hsz,8); uint32_t*hidx=calloc(hsz,4);
  for(unsigned t=0;t<T;t++){uint64_t k;memcpy(&k,nodes+(size_t)t*lb,8);if(!k)k=1;
    uint32_t h=(uint32_t)((k*HC)>>40)&hmask;while(ht[h]&&ht[h]!=k)h=(h+1)&hmask; ht[h]=k; hidx[h]=t+1;}

  // ===== evaluator handicap: the top lambda-B bits of ONE hidden bottom-parent =====
  uint8_t rootkey[MAX_CSP_BYTES],ivx[IV_SIZE];
  hash_r_iv(rootkey,ivx,owf_key,mu,rho,lb,lambda);
  uint8_t*tree=generate_seeds(rootkey,iv,s,P);
  int aim=-1; for(unsigned t=0;t<T;t++){ if(par[t]+1>=L/2){aim=(int)t;break;} }
  if(aim<0){printf("no bottom hidden parent this signature\n");return 1;}
  uint8_t known[MAX_CSP_BYTES]; memcpy(known,NODE(tree,par[aim],lb),lb);   // only top lambda-B bits are "known"

  // ===== GENUINE self-locating search: brute-force low B bits, test child vs ALL T targets =====
  uint32_t mask=(B>=32)?0xffffffffu:((1u<<B)-1);
  uint32_t start=((uint32_t)nonce[0]*40503u+12345u)&mask;      // arbitrary public start offset
  uint8_t g[MAX_CSP_BYTES],ga[MAX_CSP_BYTES],h0[MAX_CSP_BYTES],h1[MAX_CSP_BYTES];
  uint64_t evals=0; int found=0; unsigned found_child=0, found_t=0; uint8_t foundpar[MAX_CSP_BYTES];
  for(uint32_t c=0;c<=mask && !found;c++){
    uint32_t x=(start+c)&mask; memcpy(g,known,lb); uint32_t lo; memcpy(&lo,g,4); lo=(lo&~mask)|x; memcpy(g,&lo,4);
    xor_u8_array(g,const0,ga,lb); tccr_hash(ga,s,iv,h0,lambda); evals++;   // -> would be the left child
    xor_u8_array(g,const1,ga,lb); tccr_hash(ga,s,iv,h1,lambda); evals++;   // -> would be the right child
    for(int which=0;which<2 && !found;which++){ uint8_t*hh=which?h1:h0; uint64_t k; memcpy(&k,hh,8); if(!k)k=1;
      uint32_t idx=(uint32_t)((k*HC)>>40)&hmask;
      while(ht[idx]){ if(ht[idx]==k){ unsigned t=hidx[idx]-1;
          if(!memcmp(hh,nodes+(size_t)t*lb,lb)){ memcpy(foundpar,g,lb); found_child=which; found_t=t; found=1; break; } }
        idx=(idx+1)&hmask; } }
  }
  if(!found){printf("RESULT: search missed (increase B)\n");return 1;}

  // ===== everything below uses only public data + the discovered target index found_t =====
  // map the hit back to the true parent value: const0/const1 differ only in bit 0 (inside the window),
  // so a which-branch hit is the b_bit-branch hit with bit 0 adjusted.
  unsigned b_bit=(chi[found_t]==2*par[found_t]+2)?1:0;
  uint8_t truep[MAX_CSP_BYTES]; memcpy(truep,foundpar,lb); truep[0]^=(uint8_t)(found_child^b_bit);
  int self_ok = (found_t==(unsigned)aim) && !memcmp(truep,NODE(tree,par[found_t],lb),lb); // evaluator check only
  printf("set lambda=%u B=%u T=%u : HIT after %llu TCCR evals (model 2^B/2=%.0f); discovered target=%u (aimed %d); recovered node == true hidden node: %s\n",
    lambda,B,T,(unsigned long long)evals,(double)(1u<<(B>31?31:B))/2,found_t,aim,self_ok?"YES":"NO");

  unsigned hidden_child=2*par[found_t]+1+(chi[found_t]==2*par[found_t]+1);
  uint8_t t2[MAX_CSP_BYTES]; memcpy(t2,truep,lb); if(hidden_child==2*par[found_t]+2)t2[0]^=1;
  uint8_t sd_hid[MAX_CSP_BYTES]; tccr_hash(t2,s,iv,sd_hid,lambda);
  int alpha=-1; for(unsigned i=0;i<tau;i++) if(hid_leaf[i]==hidden_child) alpha=(int)i;
  uint8_t com[2*MAX_CSP_BYTES]; prg_2_lambda(sd_hid,iv,0,com,lambda);
  printf("  hidden leaf (alpha=%d) commitment matches signature: %s\n",alpha,
    (alpha>=0&&!memcmp(com,coms+(size_t)alpha*2*lb,2*lb))?"YES":"NO");
  bavc_rec_t rec; uint8_t hcom[2*MAX_CSP_BYTES]; rec.h=hcom; rec.s=malloc((L-tau)*lb);
  bavc_reconstruct(&rec,decom,delta,iv,mu,s,P);
  const uint8_t*sp=rec.s; for(int i=0;i<alpha;i++) sp+=(bavc_max_node_index(i,P->tau1,P->k)-1)*lb;
  unsigned Na=bavc_max_node_index(alpha,P->tau1,P->k); uint8_t*sda=malloc(Na*lb);
  for(unsigned j=0,q=0;j<Na;j++){ if(j==delta[alpha])memcpy(sda+j*lb,sd_hid,lb); else memcpy(sda+j*lb,sp+(q++)*lb,lb); }
  uint8_t*ua=calloc(1,ehb),*vtmp=calloc(MAX_DEPTH,ehb); convert_to_vole(iv,sda,false,alpha,ehb,ua,vtmp,P);
  uint8_t*u0=calloc(1,ehb); if(alpha==0)memcpy(u0,ua,ehb); else xor_u8_array(ua,dsignature_c(sig,alpha-1,P),u0,ehb);
  uint8_t wrec[1024]={0}; xor_u8_array(dsignature_d(sig,P),u0,wrec,ellb); if(ell%8)wrec[ellb-1]&=(uint8_t)((1u<<(ell%8))-1);
  uint8_t wtrue[1024]={0}; memcpy(wtrue,witness,ellb); if(ell%8)wtrue[ellb-1]&=(uint8_t)((1u<<(ell%8))-1);
  printf("  recovered witness == signer witness: %s\n",!memcmp(wrec,wtrue,ellb)?"YES":"NO");
  uint8_t fake_coin[MAX_CSP_BYTES],rho2[64],msg2[40]; get_random_number(&drng_algorithm,fake_coin,lambda);
  get_random_number(&drng_algorithm,rho2,lambda); memset(msg2,0x42,sizeof msg2);
  voleith_sign(sig2,msg2,sizeof msg2,fake_coin,pk,pk+in_sz,wrec,rho2,lb,P);   // note: pk, not sk; fake coin key
  int acc=sig_verify(pk,a,sig2,snl,msg2,sizeof msg2)==0;
  wrec[0]^=1; voleith_sign(sig2,msg2,sizeof msg2,fake_coin,pk,pk+in_sz,wrec,rho2,lb,P);
  int ctl=sig_verify(pk,a,sig2,snl,msg2,sizeof msg2)==0;
  printf("  forged fresh message accepted: %s ; control(flip 1 witness bit): %s\n",acc?"YES":"NO",ctl?"YES":"NO");
  int ok = self_ok && acc && !ctl;
  printf(ok?"RESULT: GENUINE SELF-LOCATING SEARCH -> KEY RECOVERY -> FORGERY OK\n":"RESULT: FAILED\n");
  return !ok;
}
