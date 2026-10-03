/* Optimized faithful TRIKE-2 threshold bit-flipping decoder, runtime r.
 * Same constants/algorithm as decoder.c. Incremental syndrome updates,
 * reusable buffers. Modes: dfr, gjs (block-0 distance-spectrum correlation). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#define D 35
#define T 263
#define N0 3
#define DELTA 4
#define ITERS 7
#define COA_FP (26330727.0/1e10)
#define COB_FP (1652.0/1e2)

static uint32_t R, N; static size_t SB;

static uint64_t rs[4];
static inline uint64_t rotl(uint64_t x,int k){return (x<<k)|(x>>(64-k));}
static uint64_t rnd(void){uint64_t r_=rotl(rs[1]*5,7)*9;uint64_t t=rs[1]<<17;rs[2]^=rs[0];rs[3]^=rs[1];rs[1]^=rs[2];rs[0]^=rs[3];rs[2]^=t;rs[3]=rotl(rs[3],45);return r_;}
static void seed_rng(uint64_t s){for(int i=0;i<4;i++){s^=s>>12;s^=s<<25;s^=s>>27;rs[i]=s*0x2545F4914F6CDD1DULL;}for(int i=0;i<16;i++)rnd();}
static inline uint32_t rnd_below(uint32_t m){return (uint32_t)(((__uint128_t)rnd()*m)>>64);}
static void sample_distinct(uint32_t *idx,uint32_t len,uint32_t w){
    for(uint32_t i=0;i<w;i++){while(1){uint32_t c=rnd_below(len);int dup=0;for(uint32_t j=0;j<i;j++)if(idx[j]==c){dup=1;break;}if(!dup){idx[i]=c;break;}}}
}

/* reusable buffers */
static uint8_t *s_buf;          /* residual syndrome, SB bytes */
static uint32_t *cnt;           /* R counters */
static uint32_t *flips;         /* flip list */

static inline void xor_col(uint8_t *s,const uint32_t *H,uint32_t i){
    for(uint32_t k=0;k<D;k++){uint32_t p=i+H[k];if(p>=R)p-=R;s[p>>3]^=(1u<<(p&7));}
}
static inline uint32_t hw(const uint8_t *w){uint32_t c=0;for(size_t i=0;i<SB;i++)c+=__builtin_popcount(w[i]);return c;}
static inline uint32_t get_threshold(uint32_t sum_init,uint32_t unsat,size_t iter){
    double Tp=COA_FP*sum_init+COB_FP;double M=(D+1.0)/2.0;uint32_t t=0;
    if(iter==0)t=(uint32_t)ceil(Tp)+DELTA;
    else if(iter==1)t=(uint32_t)ceil((2.0*Tp+M)/3.0)+DELTA;
    else if(iter==2)t=(uint32_t)ceil((Tp+2.0*M)/3.0)+DELTA;
    else t=(uint32_t)ceil(M)+DELTA;
    uint32_t fs=(uint32_t)ceil(COA_FP*unsat+COB_FP);
    uint32_t mask=-(fs<t);return (t&~mask)|(fs&mask);
}
static void calc_upc(const uint8_t *s,const uint32_t *idx,uint32_t *c){
    for(uint32_t i=0;i<R;i++){uint32_t cc=0;for(uint32_t k=0;k<D;k++){uint32_t p=i+idx[k];if(p>=R)p-=R;cc+=(s[p>>3]>>(p&7))&1;}c[i]=cc;}
}
/* decode: returns 1 if decoded error (d) equals injected error (e). d tracked as support-diff via s.
 * We track estimated error implicitly: success iff residual syndrome becomes 0 AND #flips reproduce e.
 * To verify exact e recovery we track decoded bytes de[3]. */
static uint8_t *de0,*de1,*de2, *ee0,*ee1,*ee2;
static int decode_trial(const uint32_t *h0,const uint32_t *h1,const uint32_t *h2,
    const uint32_t *e0,uint32_t t0,const uint32_t *e1,uint32_t t1,const uint32_t *e2,uint32_t t2){
    memset(s_buf,0,SB);
    memset(de0,0,SB);memset(de1,0,SB);memset(de2,0,SB);
    /* initial residual syndrome = H*e */
    for(uint32_t a=0;a<t0;a++)xor_col(s_buf,h0,e0[a]);
    for(uint32_t a=0;a<t1;a++)xor_col(s_buf,h1,e1[a]);
    for(uint32_t a=0;a<t2;a++)xor_col(s_buf,h2,e2[a]);
    uint32_t sum_init=hw(s_buf),unsat=sum_init;
    const uint32_t*H[3]={h0,h1,h2}; uint8_t*DE[3]={de0,de1,de2};
    for(size_t it=0;it<ITERS;it++){
        uint32_t th=get_threshold(sum_init,unsat,it);
        /* compute all three UPC arrays on the SAME syndrome snapshot, collect flips, then apply */
        uint32_t nf=0;
        for(int b=0;b<3;b++){
            calc_upc(s_buf,H[b],cnt);
            for(uint32_t i=0;i<R;i++) if(cnt[i]>=th){ flips[nf++]=(b<<28)|i; }
        }
        /* apply flips: toggle decoded error bit and update syndrome */
        for(uint32_t f=0;f<nf;f++){ int b=flips[f]>>28; uint32_t i=flips[f]&0x0FFFFFFF;
            DE[b][i>>3]^=(1u<<(i&7)); xor_col(s_buf,H[b],i); }
        unsat=hw(s_buf);
        if(unsat==0) break;
    }
    /* success iff decoded error == injected error */
    if(memcmp(de0,ee0,SB)||memcmp(de1,ee1,SB)||memcmp(de2,ee2,SB)) return 0;
    return 1;
}

/* ---- TRIKE-2 weak-key filter (faithful to sample.c weak_key_test), runtime r ---- */
#define PARAM_S_  46
#define PARAM_SS_ 83
static uint32_t *wk_dist=NULL;
static uint64_t intra_s0(const uint32_t*idx){
    uint32_t half=(R+1)>>1;
    for(uint32_t i=1;i<D;i++)for(uint32_t j=0;j<i;j++){
        int32_t y=(int32_t)idx[j]-(int32_t)idx[i]; if(y<0)y+=R; if((uint32_t)y>=half)y=R-y; wk_dist[y]++;}
    uint64_t res=0; for(uint32_t i=0;i<half;i++){uint32_t m=wk_dist[i]; if(m>=2)res+=(uint64_t)m*(m-1)/2; wk_dist[i]=0;}
    return res;
}
static uint64_t inter_s0(const uint32_t*a,const uint32_t*b){
    for(uint32_t i=0;i<D;i++)for(uint32_t j=0;j<D;j++){
        int32_t y=(int32_t)b[j]-(int32_t)a[i]; if(y<0)y+=R; wk_dist[y]++;}
    uint64_t res=0; for(uint32_t i=0;i<R;i++){uint32_t m=wk_dist[i]; if(m>=2)res+=(uint64_t)m*(m-1)/2; wk_dist[i]=0;}
    return res;
}
static int is_weak(const uint32_t*h0,const uint32_t*h1,const uint32_t*h2){
    if(intra_s0(h0)>PARAM_S_)return 1; if(intra_s0(h1)>PARAM_S_)return 1; if(intra_s0(h2)>PARAM_S_)return 1;
    if(inter_s0(h0,h1)>PARAM_SS_)return 1; if(inter_s0(h1,h2)>PARAM_SS_)return 1; if(inter_s0(h2,h0)>PARAM_SS_)return 1;
    return 0;
}
/* plant an arithmetic progression of length f (Type I with parameter f; gives mu(delta)>=f-1) */
static void sample_planted(uint32_t*idx,uint32_t f){
    uint32_t half=(R-1)/2; uint32_t delta=1+rnd_below(half); uint32_t l=rnd_below(R);
    for(uint32_t i=0;i<f;i++){uint64_t p=(uint64_t)l+(uint64_t)i*delta; idx[i]=(uint32_t)(p%R);}
    for(uint32_t i=f;i<D;i++){while(1){uint32_t c=rnd_below(R);int dup=0;for(uint32_t j=0;j<i;j++)if(idx[j]==c){dup=1;break;}if(!dup){idx[i]=c;break;}}}
}
static void supp_to_bytes(uint8_t *b,const uint32_t *idx,uint32_t w){memset(b,0,SB);for(uint32_t i=0;i<w;i++)b[idx[i]>>3]|=(1u<<(idx[i]&7));}

int main(int argc,char**argv){
    if(argc<5){fprintf(stderr,"usage: %s dfr|gjs <r> <trials> <seed>\n",argv[0]);return 1;}
    const char*mode=argv[1]; R=strtoul(argv[2],NULL,10); N=N0*R; SB=(R+7)/8;
    uint64_t trials=strtoull(argv[3],NULL,10); seed_rng(strtoull(argv[4],NULL,10));
    s_buf=malloc(SB);cnt=malloc(sizeof(uint32_t)*R);flips=malloc(sizeof(uint32_t)*3*R);
    de0=malloc(SB);de1=malloc(SB);de2=malloc(SB);ee0=malloc(SB);ee1=malloc(SB);ee2=malloc(SB);
    uint32_t h0[D],h1[D],h2[D];

    if(!strcmp(mode,"dfr")){
        uint64_t fails=0;
        for(uint64_t tr=0;tr<trials;tr++){
            sample_distinct(h0,R,D);sample_distinct(h1,R,D);sample_distinct(h2,R,D);
            uint32_t eidx[T]; sample_distinct(eidx,N,T);
            uint32_t e0[T],e1[T],e2[T],t0=0,t1=0,t2=0;
            for(uint32_t i=0;i<T;i++){uint32_t p=eidx[i];if(p<R)e0[t0++]=p;else if(p<2*R)e1[t1++]=p-R;else e2[t2++]=p-2*R;}
            supp_to_bytes(ee0,e0,t0);supp_to_bytes(ee1,e1,t1);supp_to_bytes(ee2,e2,t2);
            if(!decode_trial(h0,h1,h2,e0,t0,e1,t1,e2,t2))fails++;
        }
        printf("SCALED-DFR r=%u n=%u d=%d t=%d trials=%llu fails=%llu rate=%.6e\n",R,N,D,T,(unsigned long long)trials,(unsigned long long)fails,(double)fails/(double)trials);
    } else if(!strcmp(mode,"gjs")){
        sample_distinct(h0,R,D);sample_distinct(h1,R,D);sample_distinct(h2,R,D);
        uint32_t half=R/2+1;
        uint64_t*fail_dist=calloc(half,sizeof(uint64_t)),*tot_dist=calloc(half,sizeof(uint64_t));
        uint8_t*inspec=calloc(half,1),*present=calloc(half,1);
        for(uint32_t i=0;i<D;i++)for(uint32_t j=i+1;j<D;j++){int dd=abs((int)h0[i]-(int)h0[j]);if((uint32_t)dd>R/2)dd=R-dd;inspec[dd]=1;}
        uint64_t fails=0;
        for(uint64_t tr=0;tr<trials;tr++){
            uint32_t eidx[T]; sample_distinct(eidx,N,T);
            uint32_t e0[T],e1[T],e2[T],t0=0,t1=0,t2=0;
            for(uint32_t i=0;i<T;i++){uint32_t p=eidx[i];if(p<R)e0[t0++]=p;else if(p<2*R)e1[t1++]=p-R;else e2[t2++]=p-2*R;}
            supp_to_bytes(ee0,e0,t0);supp_to_bytes(ee1,e1,t1);supp_to_bytes(ee2,e2,t2);
            memset(present,0,half);
            for(uint32_t i=0;i<t0;i++)for(uint32_t j=i+1;j<t0;j++){int dd=abs((int)e0[i]-(int)e0[j]);if((uint32_t)dd>R/2)dd=R-dd;present[dd]=1;}
            int ok=decode_trial(h0,h1,h2,e0,t0,e1,t1,e2,t2);
            for(uint32_t dd=1;dd<half;dd++)if(present[dd]){tot_dist[dd]++;if(!ok)fail_dist[dd]++;}
            if(!ok)fails++;
        }
        double in_num=0,in_den=0,out_num=0,out_den=0;uint32_t in_cnt=0,out_cnt=0,specsz=0;
        for(uint32_t d=1;d<half;d++)specsz+=inspec[d];
        for(uint32_t dd=1;dd<half;dd++){if(tot_dist[dd]<100)continue;double fr=(double)fail_dist[dd]/(double)tot_dist[dd];
            if(inspec[dd]){in_num+=fr;in_den+=1;in_cnt++;}else{out_num+=fr;out_den+=1;out_cnt++;}}
        printf("SCALED-GJS r=%u trials=%llu fails=%llu DFR=%.4e spec=%u\n",R,(unsigned long long)trials,(unsigned long long)fails,(double)fails/(double)trials,specsz);
        printf("  mean P(fail|dist present): IN=%.6e (nd=%u) OUT=%.6e (nd=%u) ratio=%.4f\n",
            in_den?in_num/in_den:0,in_cnt,out_den?out_num/out_den:0,out_cnt,(out_num>0)?(in_num/in_den)/(out_num/out_den):0.0);
        char fn[64]; snprintf(fn,64,"gjs_dist_%u.csv",R); FILE*f=fopen(fn,"w"); fprintf(f,"dist,inspec,fail,tot\n");
        for(uint32_t dd=1;dd<half;dd++)if(tot_dist[dd]>0)fprintf(f,"%u,%u,%llu,%llu\n",dd,inspec[dd],(unsigned long long)fail_dist[dd],(unsigned long long)tot_dist[dd]);
        fclose(f);
    } else if(!strcmp(mode,"gjs2")){
        /* multiplicity-based GJS signal: elevation of distance multiplicity among failures */
        sample_distinct(h0,R,D);sample_distinct(h1,R,D);sample_distinct(h2,R,D);
        uint32_t half=R/2+1;
        double *mf=calloc(half,sizeof(double)),*ma=calloc(half,sizeof(double));
        uint8_t *inspec=calloc(half,1); uint32_t *mult=calloc(half,sizeof(uint32_t));
        for(uint32_t i=0;i<D;i++)for(uint32_t j=i+1;j<D;j++){int dd=abs((int)h0[i]-(int)h0[j]);if((uint32_t)dd>R/2)dd=R-dd;inspec[dd]=1;}
        uint32_t specsz=0; for(uint32_t d=1;d<half;d++)specsz+=inspec[d];
        uint64_t fails=0;
        for(uint64_t tr=0;tr<trials;tr++){
            uint32_t eidx[T]; sample_distinct(eidx,N,T);
            uint32_t e0[T],e1[T],e2[T],t0=0,t1=0,t2=0;
            for(uint32_t i=0;i<T;i++){uint32_t p=eidx[i];if(p<R)e0[t0++]=p;else if(p<2*R)e1[t1++]=p-R;else e2[t2++]=p-2*R;}
            supp_to_bytes(ee0,e0,t0);supp_to_bytes(ee1,e1,t1);supp_to_bytes(ee2,e2,t2);
            /* multiplicity of each distance in e0 */
            for(uint32_t i=0;i<t0;i++)for(uint32_t j=i+1;j<t0;j++){int dd=abs((int)e0[i]-(int)e0[j]);if((uint32_t)dd>R/2)dd=R-dd;mult[dd]++;}
            int ok=decode_trial(h0,h1,h2,e0,t0,e1,t1,e2,t2);
            for(uint32_t dd=1;dd<half;dd++)if(mult[dd]){ ma[dd]+=mult[dd]; if(!ok)mf[dd]+=mult[dd]; mult[dd]=0; }
            if(!ok)fails++;
        }
        /* elevation[d] = (mf[d]/fails) / (ma[d]/trials) ; mean over in-spec vs out-spec */
        double in_s=0,out_s=0; uint32_t in_c=0,out_c=0;
        for(uint32_t dd=1;dd<half;dd++){ if(ma[dd]<1)continue;
            double elev=(mf[dd]/(double)fails)/(ma[dd]/(double)trials);
            if(inspec[dd]){in_s+=elev;in_c++;}else{out_s+=elev;out_c++;} }
        double inm=in_c?in_s/in_c:0, outm=out_c?out_s/out_c:0;
        /* also variance for a z-score */
        double in_v=0,out_v=0;
        for(uint32_t dd=1;dd<half;dd++){ if(ma[dd]<1)continue;
            double elev=(mf[dd]/(double)fails)/(ma[dd]/(double)trials);
            if(inspec[dd])in_v+=(elev-inm)*(elev-inm); else out_v+=(elev-outm)*(elev-outm); }
        in_v/= (in_c>1?in_c-1:1); out_v/=(out_c>1?out_c-1:1);
        double se=sqrt(in_v/in_c+out_v/out_c);
        printf("SCALED-GJS2 r=%u trials=%llu fails=%llu DFR=%.4e spec=%u\n",R,(unsigned long long)trials,(unsigned long long)fails,(double)fails/(double)trials,specsz);
        printf("  mean multiplicity-elevation among failures: IN-spec=%.6f (n=%u) OUT-spec=%.6f (n=%u)\n",inm,in_c,outm,out_c);
        printf("  IN-OUT = %+.6f   SE=%.6f   z=%.2f\n", inm-outm, se, se>0?(inm-outm)/se:0.0);
    } else if(!strcmp(mode,"wk")||!strcmp(mode,"wkrand")){
        /* DFR restricted to filter-PASSING keys; "wk" plants an AP of length f in block 0 */
        uint32_t f = (argc>5)? (uint32_t)strtoul(argv[5],NULL,10) : 0;
        int plant = !strcmp(mode,"wk");
        wk_dist=calloc(R,sizeof(uint32_t));
        uint64_t fails=0,rejected=0,done=0;
        while(done<trials){
            if(plant) sample_planted(h0,f); else sample_distinct(h0,R,D);
            sample_distinct(h1,R,D);sample_distinct(h2,R,D);
            if(is_weak(h0,h1,h2)){rejected++;continue;}
            done++;
            uint32_t eidx[T]; sample_distinct(eidx,N,T);
            uint32_t e0[T],e1[T],e2[T],t0=0,t1=0,t2=0;
            for(uint32_t i=0;i<T;i++){uint32_t p=eidx[i];if(p<R)e0[t0++]=p;else if(p<2*R)e1[t1++]=p-R;else e2[t2++]=p-2*R;}
            supp_to_bytes(ee0,e0,t0);supp_to_bytes(ee1,e1,t1);supp_to_bytes(ee2,e2,t2);
            if(!decode_trial(h0,h1,h2,e0,t0,e1,t1,e2,t2))fails++;
        }
        printf("SCALED-WK mode=%s f=%u r=%u trials=%llu fails=%llu rate=%.6e filter_rejected=%llu (%.3f%% of drawn)\n",
            mode,f,R,(unsigned long long)trials,(unsigned long long)fails,(double)fails/(double)trials,
            (unsigned long long)rejected,100.0*rejected/(double)(rejected+done));
    }
    return 0;
}
