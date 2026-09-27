/* Bilinear estimator over BiT signatures (PUBLIC transcripts only: z0, z_tail, c).
 * NO secret key is ever read here.
 * Default: sigma = sign(<z0,c>) (recovers the shared bimodal sign) -> acc2.bin.
 * "ctrl": replaces sigma with an INDEPENDENT reproducible random +-1 per signature,
 *         i.e. models a scheme WITHOUT the shared bimodal bit -> acc2_ctrl.bin.
 * Usage: ./est2 [ctrl] sigfile...  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define N 256
#define L 3
static double acc[L][N];
static int16_t z0[N], zt[L][N], cc[N];
/* small reproducible xorshift for the control's independent signs */
static uint64_t st=0x9E3779B97F4A7C15ULL;
static int rnd_sign(void){ st^=st<<13; st^=st>>7; st^=st<<17; return (st&1)?1:-1; }
int main(int argc,char**argv){
  int ctrl=0, a0=1;
  if(argc>1 && strcmp(argv[1],"ctrl")==0){ ctrl=1; a0=2; }
  long done=0;
  for(int f=a0;f<argc;f++){ FILE*fs=fopen(argv[f],"rb");
    if(!fs){ fprintf(stderr,"est2: cannot open %s\n",argv[f]); return 1; }  /* never skip data silently */
    while(1){ if(fread(z0,2,N,fs)!=N)break; int ok=1;
      for(int i=0;i<L;i++) if(fread(zt[i],2,N,fs)!=N){ok=0;break;} if(!ok)break;
      if(fread(cc,2,N,fs)!=N)break;
      int sigma;
      if(ctrl){ sigma=rnd_sign(); }         /* control: sign independent of transcript */
      else { long dot=0; for(int j=0;j<N;j++) if(cc[j]) dot+=(long)z0[j]*cc[j];
             sigma = dot>=0?1:-1; }          /* recover the shared bimodal sign */
      for(int j=0;j<N;j++){ if(!cc[j])continue; int cj=cc[j];
        for(int i=0;i<L;i++){int16_t*z=zt[i];
          for(int k=0;k<N;k++){int idx=j+k,sg=1;if(idx>=N){idx-=N;sg=-1;}acc[i][k]+=(double)sigma*cj*sg*z[idx];}}}
      done++;
    } fclose(fs);
  }
  const char*out = ctrl?"acc2_ctrl.bin":"acc2.bin";
  FILE*fo=fopen(out,"wb"); fwrite(acc,sizeof(double),L*N,fo); fclose(fo);
  fprintf(stderr,"est2 %s done %ld sigs -> %s\n", ctrl?"[CONTROL rand-sign]":"", done, out);
  return 0;
}
