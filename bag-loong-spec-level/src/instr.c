/*
 * BAG-Loong (ngcc kem-03) analysis harness.
 *
 * Built against the *patched* reference tree (secret random supports, i.e. with the
 * kem-03-3 sampler defect repaired).  It includes loong_pke.c directly so that the
 * file-static helpers (logical_vec_decode, generate_public_objects, matrix_mul, ...)
 * are reachable; loong_pke.c is therefore excluded from the link.
 *
 * Modes
 *   rank  <keys>   per key: dim Supp(X), dim Supp(Y), dim(Supp(X)+Supp(Y)), and the
 *                  per-column rank of the error vector (X_j | Y_j) of the
 *                  [2n, n]_{q^m} syndrome instance S_j = [H | I] (X_j ; Y_j).
 *   resid <keys> <ct>  rank of the residual decryption noise R2 Y - R1 X + E,
 *                  against the augmented-Gabidulin radius floor((n'-k+eps)/2).
 *   kat   <keys>   KEM keygen/encaps/decaps round-trip (correctness under the patch).
 *   dump  <file>   one instance written for the external solver: m, n, n1, H, S,
 *                  and the true X, Y (used only to check a recovered solution).
 */
#include "loong_pke.c"

#include <stdio.h>
#include <string.h>

#include "drng.h"
#include "loong_api_random.h"
#include "loong_kem.h"
#include "parsing.h"

DRNG_ctx drng_algorithm;

#define AXY_UNION (LOONG_AXY_00 + LOONG_AXY_11 - LOONG_AXY_01)
#define AR_UNION (LOONG_AR_00 + LOONG_AR_11 - LOONG_AR_01)
#define DELTA ((LOONG_N_PRIME - LOONG_K + LOONG_EPSILON) / 2)

/* Recompute Y = S + H*X from the public key and the secret key. */
static int recover_xy(rbc_elt *x, rbc_elt *y, rbc_elt *h, const unsigned char *pk,
                      const unsigned char *sk_prime)
{
	rbc_elt *g = (rbc_elt *)calloc(LOONG_PKE_L, sizeof(*g));
	rbc_elt *s = (rbc_elt *)calloc(LOONG_PKE_XS_SIZE, sizeof(*s));
	int st = LOONG_ERR_ALLOC;

	if (g == 0 || s == 0) {
		goto done;
	}
	st = generate_public_objects(g, h, pk + LOONG_PK_SEED_OFFSET,
	                             LOONG_PK_SEED_BYTES);
	if (st != LOONG_SUCCESS) {
		goto done;
	}
	st = logical_vec_decode(x, LOONG_PKE_XS_SIZE, sk_prime + LOONG_SK_X_OFFSET,
	                        LOONG_X_OR_S_BYTES);
	if (st != LOONG_SUCCESS) {
		goto done;
	}
	st = logical_vec_decode(s, LOONG_PKE_XS_SIZE, pk + LOONG_PK_S_OFFSET,
	                        LOONG_X_OR_S_BYTES);
	if (st != LOONG_SUCCESS) {
		goto done;
	}
	/* char 2: Y = S - H*X = S + H*X */
	matrix_mul(y, h, LOONG_N, LOONG_N, x, LOONG_N1);
	vec_add_inplace(y, s, LOONG_PKE_XS_SIZE);
	st = LOONG_SUCCESS;
done:
	clear_free(g);
	clear_free(s);
	return st;
}

static int fresh_key(unsigned char *pk, unsigned char *sk_prime)
{
	unsigned char pseed[LOONG_PK_SEED_BYTES];
	unsigned char kseed[LOONG_PK_SEED_BYTES];
	int st;

	st = loong_api_random_bytes(pseed, sizeof(pseed));
	if (st != LOONG_SUCCESS) {
		return st;
	}
	st = loong_api_random_bytes(kseed, sizeof(kseed));
	if (st != LOONG_SUCCESS) {
		return st;
	}
	return loong_pke_keygen_derandomized(pk, LOONG_PK_BYTES, sk_prime,
	                                     LOONG_SK_PRIME_BYTES, pseed,
	                                     sizeof(pseed), kseed, sizeof(kseed));
}

static int mode_rank(int keys)
{
	unsigned char *pk = (unsigned char *)calloc(LOONG_PK_BYTES, 1);
	unsigned char *skp = (unsigned char *)calloc(LOONG_SK_PRIME_BYTES, 1);
	rbc_elt *x = (rbc_elt *)calloc(LOONG_PKE_XS_SIZE, sizeof(*x));
	rbc_elt *y = (rbc_elt *)calloc(LOONG_PKE_XS_SIZE, sizeof(*y));
	rbc_elt *h = (rbc_elt *)calloc((size_t)LOONG_N * LOONG_N, sizeof(*h));
	rbc_elt *col = (rbc_elt *)calloc(2U * LOONG_N, sizeof(*col));
	rbc_elt *both = (rbc_elt *)calloc(2U * LOONG_PKE_XS_SIZE, sizeof(*both));
	int bad = 0;
	int k;

	if (!pk || !skp || !x || !y || !h || !col || !both) {
		return 2;
	}
	printf("%s n=%u m=%u n1=%u A_XY=[[%u,%u],[%u,%u]] union=%u (blocks separate=%u)\n",
	       LOONG_INSTANCE_NAME, LOONG_N, LOONG_M, LOONG_N1, LOONG_AXY_00,
	       LOONG_AXY_01, LOONG_AXY_10, LOONG_AXY_11, (unsigned)AXY_UNION,
	       (unsigned)(LOONG_AXY_00 + LOONG_AXY_11));
	for (k = 0; k < keys; k++) {
		unsigned int rx = 0, ry = 0, ru = 0;
		unsigned int colmax = 0, colmin = 2U * LOONG_N;
		unsigned int j, i;

		if (fresh_key(pk, skp) != LOONG_SUCCESS) {
			printf("  key %d: keygen FAILED\n", k);
			bad++;
			continue;
		}
		if (recover_xy(x, y, h, pk, skp) != LOONG_SUCCESS) {
			printf("  key %d: recover FAILED\n", k);
			bad++;
			continue;
		}
		rbc_vec_get_rank(&rx, x, LOONG_PKE_XS_SIZE);
		rbc_vec_get_rank(&ry, y, LOONG_PKE_XS_SIZE);
		rbc_vec_set(both, x, LOONG_PKE_XS_SIZE);
		rbc_vec_set(both + LOONG_PKE_XS_SIZE, y, LOONG_PKE_XS_SIZE);
		rbc_vec_get_rank(&ru, both, 2U * LOONG_PKE_XS_SIZE);
		for (j = 0; j < LOONG_N1; j++) {
			unsigned int rc = 0;
			for (i = 0; i < LOONG_N; i++) {
				rbc_elt_set(&col[i], &x[i * LOONG_N1 + j]);
				rbc_elt_set(&col[LOONG_N + i], &y[i * LOONG_N1 + j]);
			}
			rbc_vec_get_rank(&rc, col, 2U * LOONG_N);
			if (rc > colmax) {
				colmax = rc;
			}
			if (rc < colmin) {
				colmin = rc;
			}
		}
		if (rx != LOONG_AXY_00 || ry != LOONG_AXY_11 || ru != AXY_UNION ||
		    colmax > AXY_UNION) {
			bad++;
		}
		printf("  key %-3d dimSuppX=%u dimSuppY=%u dim(SuppX+SuppY)=%u "
		       "per-column rank(X_j|Y_j) min=%u max=%u\n",
		       k, rx, ry, ru, colmin, colmax);
	}
	printf("RESULT rank: keys=%d violations=%d (expect union=%u, every column "
	       "rank <= %u)\n",
	       keys, bad, (unsigned)AXY_UNION, (unsigned)AXY_UNION);
	return bad != 0;
}

static int mode_resid(int keys, int cts)
{
	unsigned char *pk = (unsigned char *)calloc(LOONG_PK_BYTES, 1);
	unsigned char *skp = (unsigned char *)calloc(LOONG_SK_PRIME_BYTES, 1);
	unsigned long long mlen = loong_pke_get_message_len_bytes();
	unsigned char *msg = (unsigned char *)calloc((size_t)mlen, 1);
	unsigned char *got = (unsigned char *)calloc((size_t)mlen, 1);
	unsigned char *ct = (unsigned char *)calloc(LOONG_PKE_CT_BYTES, 1);
	unsigned char theta[LOONG_G_BYTES];
	unsigned int lo = 0xffffffffU, hi = 0;
	long long sum = 0;
	int n = 0, fail = 0, k, t;

	if (!pk || !skp || !msg || !got || !ct) {
		return 2;
	}
	for (k = 0; k < keys; k++) {
		if (fresh_key(pk, skp) != LOONG_SUCCESS) {
			return 2;
		}
		for (t = 0; t < cts; t++) {
			unsigned int rr = 0;
			int re;
			if (loong_api_random_bytes(msg, mlen) != LOONG_SUCCESS ||
			    loong_api_random_bytes(theta, sizeof(theta)) !=
			            LOONG_SUCCESS) {
				return 2;
			}
			/* clear the pad bits so the message is a valid F_{q^m}^k vector */
			{
				unsigned long long bits = (unsigned long long)LOONG_K * LOONG_M;
				unsigned long long i2;
				for (i2 = bits; i2 < mlen * 8ULL; i2++) {
					msg[i2 / 8] &= (unsigned char)~(1U << (7U - i2 % 8));
				}
			}
			re = loong_pke_encrypt_derandomized(ct, LOONG_PKE_CT_BYTES, pk,
			                                    LOONG_PK_BYTES, msg, mlen,
			                                    theta, sizeof(theta));
			if (re != LOONG_SUCCESS) {
				if (t < 2) {
					printf("  encrypt status=%d\n", re);
				}
				fail++;
				continue;
			}
			{
				int rd = loong_pke_decrypt_with_residual_rank(
					got, mlen, &rr, skp, LOONG_SK_PRIME_BYTES, ct,
					LOONG_PKE_CT_BYTES);
				if (rd != LOONG_SUCCESS) {
					if (t < 2) {
						printf("  decrypt status=%d residual=%u\n", rd, rr);
					}
					fail++;
					continue;
				}
			}
			if (memcmp(msg, got, (size_t)mlen) != 0) {
				fail++;
			}
			if (rr < lo) {
				lo = rr;
			}
			if (rr > hi) {
				hi = rr;
			}
			sum += rr;
			n++;
		}
	}
	printf("RESULT resid %s: n=%d residual rank min=%u max=%u mean=%.2f "
	       "decoder radius delta=%u  A_R union=%u (blocks separate=%u) "
	       "decrypt_failures=%d\n",
	       LOONG_INSTANCE_NAME, n, lo, hi, n ? (double)sum / n : 0.0,
	       (unsigned)DELTA, (unsigned)AR_UNION,
	       (unsigned)(LOONG_AR_00 + LOONG_AR_11), fail);
	return fail != 0;
}

/*
 * Measure the true residual decryption noise  R2 Y - R1 X + E  directly from the
 * secrets, bypassing the decoder: rank of the whole vector, and the rank of its
 * tail (the n1*n2 - n' coordinates where the augmented Gabidulin codeword is zero,
 * whose support dimension the decoder assumes is at most eps).
 */
static int mode_noise(int keys, int cts)
{
	unsigned char *pk = (unsigned char *)calloc(LOONG_PK_BYTES, 1);
	unsigned char *skp = (unsigned char *)calloc(LOONG_SK_PRIME_BYTES, 1);
	unsigned long long mlen = loong_pke_get_message_len_bytes();
	unsigned char *msg = (unsigned char *)calloc((size_t)mlen, 1);
	unsigned char *ct = (unsigned char *)calloc(LOONG_PKE_CT_BYTES, 1);
	unsigned char theta[LOONG_G_BYTES];
	rbc_elt *x = (rbc_elt *)calloc(LOONG_PKE_XS_SIZE, sizeof(*x));
	rbc_elt *y = (rbc_elt *)calloc(LOONG_PKE_XS_SIZE, sizeof(*y));
	rbc_elt *h = (rbc_elt *)calloc((size_t)LOONG_N * LOONG_N, sizeof(*h));
	rbc_elt *g = (rbc_elt *)calloc(LOONG_PKE_L, sizeof(*g));
	rbc_elt *hh = (rbc_elt *)calloc((size_t)LOONG_N * LOONG_N, sizeof(*hh));
	rbc_elt *c1 = (rbc_elt *)calloc(LOONG_PKE_C1_SIZE, sizeof(*c1));
	rbc_elt *c2 = (rbc_elt *)calloc(LOONG_PKE_C2_SIZE, sizeof(*c2));
	rbc_elt *c1x = (rbc_elt *)calloc(LOONG_PKE_C2_SIZE, sizeof(*c1x));
	rbc_elt *word = (rbc_elt *)calloc(LOONG_PKE_L, sizeof(*word));
	rbc_elt *mg = (rbc_elt *)calloc(LOONG_PKE_L, sizeof(*mg));
	rbc_elt *mv = (rbc_elt *)calloc(LOONG_K, sizeof(*mv));
	augabidulin_code code;
	unsigned int lo = 0xffffffffU, hi = 0, tlo = 0xffffffffU, thi = 0;
	int n = 0, over = 0, tover = 0, k, t;

	if (!pk || !skp || !msg || !ct || !x || !y || !h || !g || !hh || !c1 ||
	    !c2 || !c1x || !word || !mg || !mv) {
		return 2;
	}
	for (k = 0; k < keys; k++) {
		if (fresh_key(pk, skp) != LOONG_SUCCESS ||
		    recover_xy(x, y, h, pk, skp) != LOONG_SUCCESS) {
			return 2;
		}
		if (generate_public_objects(g, hh, pk + LOONG_PK_SEED_OFFSET,
		                            LOONG_PK_SEED_BYTES) != LOONG_SUCCESS ||
		    augabidulin_code_init(&code, g, LOONG_K, LOONG_PKE_L,
		                          LOONG_N_PRIME) != LOONG_SUCCESS) {
			return 2;
		}
		for (t = 0; t < cts; t++) {
			unsigned int r = 0, tr = 0;
			unsigned long long bits = (unsigned long long)LOONG_K * LOONG_M;
			unsigned long long i2;

			if (loong_api_random_bytes(msg, mlen) != LOONG_SUCCESS ||
			    loong_api_random_bytes(theta, sizeof(theta)) !=
			            LOONG_SUCCESS) {
				return 2;
			}
			for (i2 = bits; i2 < mlen * 8ULL; i2++) {
				msg[i2 / 8] &= (unsigned char)~(1U << (7U - i2 % 8));
			}
			if (loong_pke_encrypt_derandomized(ct, LOONG_PKE_CT_BYTES, pk,
			                                   LOONG_PK_BYTES, msg, mlen,
			                                   theta, sizeof(theta)) !=
			            LOONG_SUCCESS ||
			    pke_ct_core_decode(c1, c2, ct, LOONG_PKE_CT_BYTES) !=
			            LOONG_SUCCESS ||
			    logical_vec_decode(mv, LOONG_K, msg, mlen) != LOONG_SUCCESS) {
				return 2;
			}
			/* word = C2 + C1*X = Fold(mG) + (R2 Y - R1 X + E) */
			matrix_mul(c1x, c1, LOONG_N2, LOONG_N, x, LOONG_N1);
			rbc_vec_set(word, c2, LOONG_PKE_C2_SIZE);
			vec_add_inplace(word, c1x, LOONG_PKE_C2_SIZE);
			if (augabidulin_code_encode(mg, LOONG_PKE_L, &code, mv,
			                            LOONG_K) != LOONG_SUCCESS) {
				return 2;
			}
			vec_add_inplace(mg, word, LOONG_PKE_L); /* mg := noise */
			rbc_vec_get_rank(&r, mg, LOONG_PKE_L);
			rbc_vec_get_rank(&tr, mg + LOONG_N_PRIME,
			                 LOONG_PKE_L - LOONG_N_PRIME);
			if (r < lo) {
				lo = r;
			}
			if (r > hi) {
				hi = r;
			}
			if (tr < tlo) {
				tlo = tr;
			}
			if (tr > thi) {
				thi = tr;
			}
			over += r > DELTA;
			tover += tr > LOONG_EPSILON;
			n++;
		}
	}
	printf("RESULT noise %s: n=%d  rank(R2Y-R1X+E) in [%u,%u] vs delta=%u "
	       "(exceeded %d/%d)   tail support dim in [%u,%u] vs eps=%u "
	       "(exceeded %d/%d)\n",
	       LOONG_INSTANCE_NAME, n, lo, hi, (unsigned)DELTA, over, n, tlo, thi,
	       (unsigned)LOONG_EPSILON, tover, n);
	return 0;
}

static int mode_kat(int keys)
{
	unsigned char *pk = (unsigned char *)calloc(LOONG_PK_BYTES, 1);
	unsigned char *sk = (unsigned char *)calloc(LOONG_SK_BYTES, 1);
	unsigned char *ct = (unsigned char *)calloc(LOONG_CT_BYTES, 1);
	unsigned char *ss = (unsigned char *)calloc(LOONG_SS_BYTES, 1);
	unsigned char *s2 = (unsigned char *)calloc(LOONG_SS_BYTES, 1);
	int ok = 0, k;

	if (!pk || !sk || !ct || !ss || !s2) {
		return 2;
	}
	for (k = 0; k < keys; k++) {
		int rg = loong_kem_keygen(pk, LOONG_PK_BYTES, sk, LOONG_SK_BYTES);
		int re = loong_kem_encapsulate(pk, LOONG_PK_BYTES, ss, LOONG_SS_BYTES,
		                               ct, LOONG_CT_BYTES);
		int rd = loong_kem_decapsulate(sk, LOONG_SK_BYTES, ct, LOONG_CT_BYTES,
		                               s2, LOONG_SS_BYTES);
		int agree = memcmp(ss, s2, LOONG_SS_BYTES) == 0;
		if (k < 4) {
			printf("  key %d keygen=%d encaps=%d decaps=%d agree=%d\n", k, rg,
			       re, rd, agree);
		}
		ok += (rg == LOONG_SUCCESS && re == LOONG_SUCCESS &&
		       rd == LOONG_SUCCESS && agree);
	}
	printf("RESULT kat %s: %d/%d round-trips agree\n", LOONG_INSTANCE_NAME, ok,
	       keys);
	return ok != keys;
}

static int mode_dump(const char *path)
{
	unsigned char *pk = (unsigned char *)calloc(LOONG_PK_BYTES, 1);
	unsigned char *skp = (unsigned char *)calloc(LOONG_SK_PRIME_BYTES, 1);
	rbc_elt *x = (rbc_elt *)calloc(LOONG_PKE_XS_SIZE, sizeof(*x));
	rbc_elt *y = (rbc_elt *)calloc(LOONG_PKE_XS_SIZE, sizeof(*y));
	rbc_elt *h = (rbc_elt *)calloc((size_t)LOONG_N * LOONG_N, sizeof(*h));
	unsigned long long hb = ((unsigned long long)LOONG_N * LOONG_N * LOONG_M + 7) / 8;
	unsigned long long vb = LOONG_VEC_N_N1_BYTES;
	unsigned char *buf = (unsigned char *)calloc((size_t)hb, 1);
	FILE *f = 0;
	unsigned int terms[] = RBC_FIELD_POLY_TERMS;
	unsigned int hdr[5];

	if (!pk || !skp || !x || !y || !h || !buf) {
		return 2;
	}
	if (fresh_key(pk, skp) != LOONG_SUCCESS ||
	    recover_xy(x, y, h, pk, skp) != LOONG_SUCCESS) {
		return 2;
	}
	f = fopen(path, "wb");
	if (!f) {
		return 2;
	}
	hdr[0] = LOONG_M;
	hdr[1] = LOONG_N;
	hdr[2] = LOONG_N1;
	hdr[3] = AXY_UNION;
	hdr[4] = RBC_FIELD_POLY_TERMS_COUNT;
	fwrite(hdr, sizeof(hdr[0]), 5, f);
	fwrite(terms, sizeof(terms[0]), RBC_FIELD_POLY_TERMS_COUNT, f);
	logical_vec_encode(buf, hb, h, LOONG_N * LOONG_N);
	fwrite(buf, 1, (size_t)hb, f);
	fwrite(pk + LOONG_PK_S_OFFSET, 1, (size_t)vb, f); /* S */
	fwrite(skp + LOONG_SK_X_OFFSET, 1, (size_t)vb, f); /* true X */
	memset(buf, 0, (size_t)hb);
	logical_vec_encode(buf, vb, y, LOONG_PKE_XS_SIZE);
	fwrite(buf, 1, (size_t)vb, f); /* true Y */
	fclose(f);
	printf("RESULT dump %s -> %s (m=%u n=%u n1=%u union=%u)\n",
	       LOONG_INSTANCE_NAME, path, LOONG_M, LOONG_N, LOONG_N1,
	       (unsigned)AXY_UNION);
	return 0;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "rank";
	unsigned char seed[64];
	int a = argc > 2 ? atoi(argv[2]) : 8;
	int b = argc > 3 ? atoi(argv[3]) : 8;
	int sb = argc > 4 ? atoi(argv[4]) : 1;

	memset(seed, 0, sizeof(seed));
	seed[0] = (unsigned char)sb;
	seed[1] = (unsigned char)(sb >> 8);
	init_random_number(&drng_algorithm, seed, sizeof(seed));

	if (!strcmp(mode, "rank")) {
		return mode_rank(a);
	}
	if (!strcmp(mode, "resid")) {
		return mode_resid(a, b);
	}
	if (!strcmp(mode, "noise")) {
		return mode_noise(a, b);
	}
	if (!strcmp(mode, "kat")) {
		return mode_kat(a);
	}
	if (!strcmp(mode, "dump")) {
		return mode_dump(argc > 2 ? argv[2] : "instance.bin");
	}
	fprintf(stderr, "unknown mode %s\n", mode);
	return 2;
}
