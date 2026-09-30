/* Count ow_pke_keypair retries (the mont2_inverse early-exit path, CT-5). */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "api.h"
#include "owpke.h"
#include "poly.h"
extern long long g_inv_fail;
int main(int argc,char**argv){
    int M=argc>1?atoi(argv[1]):20000;
    uint8_t *pk=malloc(KEM_CCA_PK_BYTES),*sk=malloc(KEM_CCA_SK_BYTES);
    g_inv_fail=0;
    for(int k=0;k<M;k++) ow_pke_keypair(pk,sk);
    printf("PARAMS=%d keygens=%d  mont2_inverse_failures(=retries)=%lld\n",PARAMS,M,g_inv_fail);
    return 0;
}
