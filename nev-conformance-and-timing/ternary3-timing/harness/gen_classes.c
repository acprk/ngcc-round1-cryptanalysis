/* Classify honest NEV ciphertexts by the amount of work the FO re-encryption's
 * rejection sampler (ternary3 inside poly_bias3_ternary) performs during
 * decapsulation.  Uses the INSTRUMENTED sample_probe.c, so this binary is only
 * used for classification, never for timing. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "api.h"
#include "cca.h"

extern long long g_scan, g_rej, g_refill, g_veciter, g_tailacc;

int main(int argc, char **argv) {
    int M = argc > 1 ? atoi(argv[1]) : 20000;
    const char *outpath = argc > 2 ? argv[2] : NULL;
    /* tamper=1: flip one ciphertext byte so kem_cca_dec REJECTS.  The FO
       re-encryption (and hence the rejection sampler) still runs before verify,
       so this models an attacker-chosen decapsulation query. */
    int tamper = argc > 3 ? atoi(argv[3]) : 0;
    uint8_t *pk = malloc(KEM_CCA_PK_BYTES), *sk = malloc(KEM_CCA_SK_BYTES);
    uint8_t *ct = malloc(KEM_CCA_CT_BYTES);
    uint8_t ss1[SEED_BYTES], ss2[SEED_BYTES];
    kem_cca_keygen(pk, sk);

    long long *rej = malloc(sizeof(long long) * M);
    long long *scn = malloc(sizeof(long long) * M);
    long long *rfl = malloc(sizeof(long long) * M);
    uint8_t *cts = malloc((size_t)M * KEM_CCA_CT_BYTES);
    long long sr = 0, ss_ = 0, srf = 0, bad = 0;
    long long minr = 1 << 30, maxr = -1;

    for (int k = 0; k < M; k++) {
        kem_cca_enc(ss1, ct, pk);
        if (tamper) { ct[(k * 7919u) % PKE_OW_CT_BYTES] ^= 0x01; }
        g_scan = g_rej = g_refill = g_veciter = g_tailacc = 0;
        int rc = kem_cca_dec(ss2, ct, sk);
        if (tamper ? (rc == 0) : (rc || memcmp(ss1, ss2, SEED_BYTES))) bad++;
        rej[k] = g_rej; scn[k] = g_scan; rfl[k] = g_refill;
        memcpy(cts + (size_t)k * KEM_CCA_CT_BYTES, ct, KEM_CCA_CT_BYTES);
        sr += g_rej; ss_ += g_scan; srf += g_refill;
        if (g_rej < minr) minr = g_rej;
        if (g_rej > maxr) maxr = g_rej;
    }
    double mr = (double)sr / M, msc = (double)ss_ / M;
    double vr = 0; for (int k = 0; k < M; k++) vr += (rej[k]-mr)*(rej[k]-mr);
    vr /= M;
    printf("PARAMS=%d N=%d SEED_BYTES=%d KDF_RATE=%d ETA_R=%d COMPRESS=%d M=%d\n",
           PARAMS, PARAM_N, SEED_BYTES, KDF_RATE,
#ifdef ETA_R
           ETA_R,
#else
           -1,
#endif
           COMPRESS, M);
    printf("tamper=%d unexpected_rc=%lld\n", tamper, bad);
    printf("rejections/decap: mean=%.4f sd=%.4f min=%lld max=%lld\n", mr, (vr>0?__builtin_sqrt(vr):0.0), minr, maxr);
    printf("bytes_scanned/decap: mean=%.4f\n", msc);
    printf("refills/decap: total=%lld rate=%.3e\n", srf, (double)srf / M);

    /* histogram */
    if (maxr >= 0 && maxr - minr < 200) {
        printf("hist(rej):");
        long long *h = calloc(maxr - minr + 1, sizeof(long long));
        for (int k = 0; k < M; k++) h[rej[k]-minr]++;
        for (long long v = minr; v <= maxr; v++) if (h[v-minr]) printf(" %lld:%lld", v, h[v-minr]);
        printf("\n");
    }

    /* pick LOW / HIGH tails (disjoint), and a second LOW group for the null control */
    long long loT = (long long)(mr - 2.0*__builtin_sqrt(vr));
    long long hiT = (long long)(mr + 2.0*__builtin_sqrt(vr) + 0.999);
    int nlo=0, nhi=0;
    for (int k=0;k<M;k++){ if(rej[k]<=loT) nlo++; else if(rej[k]>=hiT) nhi++; }
    printf("thresholds: LOW<=%lld (n=%d)  HIGH>=%lld (n=%d)\n", loT, nlo, hiT, nhi);

    if (outpath) {
        FILE *f = fopen(outpath, "wb");
        uint32_t hdr[6] = {(uint32_t)PARAMS, (uint32_t)KEM_CCA_CT_BYTES,
                           (uint32_t)KEM_CCA_SK_BYTES, (uint32_t)nlo, (uint32_t)nhi, (uint32_t)M};
        fwrite(hdr, sizeof(hdr), 1, f);
        fwrite(sk, 1, KEM_CCA_SK_BYTES, f);
        /* LOW group */
        for (int k=0;k<M;k++) if(rej[k]<=loT) fwrite(cts + (size_t)k*KEM_CCA_CT_BYTES,1,KEM_CCA_CT_BYTES,f);
        /* HIGH group */
        for (int k=0;k<M;k++) if(rej[k]>=hiT) fwrite(cts + (size_t)k*KEM_CCA_CT_BYTES,1,KEM_CCA_CT_BYTES,f);
        fclose(f);
        printf("wrote %s\n", outpath);
        /* second file: every ciphertext tagged with its exact rejection count */
        char p2[512]; snprintf(p2,sizeof(p2),"%s.all",outpath);
        FILE *g = fopen(p2,"wb");
        uint32_t h2[4] = {(uint32_t)PARAMS,(uint32_t)KEM_CCA_CT_BYTES,(uint32_t)KEM_CCA_SK_BYTES,(uint32_t)M};
        fwrite(h2,sizeof(h2),1,g); fwrite(sk,1,KEM_CCA_SK_BYTES,g);
        for(int k=0;k<M;k++){ int32_t rr=(int32_t)rej[k]; fwrite(&rr,4,1,g);
            fwrite(cts+(size_t)k*KEM_CCA_CT_BYTES,1,KEM_CCA_CT_BYTES,g); }
        fclose(g); printf("wrote %s\n", p2);
    }
    return 0;
}
