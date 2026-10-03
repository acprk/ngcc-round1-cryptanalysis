#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "KEM_AlgorithmInstance.h"
#include "drng.h"
DRNG_ctx drng_algorithm;   /* NOT seeded, as an application that forgets to seed */
int main(void){
    unsigned long long pl,sl; int z=1;
    unsigned char *s=(unsigned char*)&drng_algorithm;
    for(size_t i=0;i<sizeof(drng_algorithm);i++) if(s[i]) z=0;
    printf("drng_algorithm all-zero at start: %s\n", z?"YES":"no");
    unsigned char *pk=malloc(kem_get_pk_len_bytes()),*sk=malloc(kem_get_sk_len_bytes());
    for(int c=1;c<=2;c++){ kem_keygen(pk,&pl,sk,&sl); printf("pk call#%d[0..15] = ",c);
        for(int i=0;i<16;i++)printf("%02x",pk[i]); printf("\n"); }
    return 0;
}
