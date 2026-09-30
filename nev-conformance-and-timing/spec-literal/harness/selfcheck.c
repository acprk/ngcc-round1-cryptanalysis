/* F-2 step 1: correctness proof of my literal Algorithm 11 transcription.
 *
 * The submitted cbd1 / cbd2 / cbd4 are (per NEV-review/C3-samplers.md) bit-for-bit
 * Algorithm 11 for eta = 1, 2, 4.  So the ONLY acceptable evidence that
 * cbd_eta_alg11() is a correct transcription is that it reproduces those three
 * functions coefficient-for-coefficient on the same input bytes.  If that fails,
 * the bug is mine, not the submission's.
 *
 * Then, and only then, the same function is applied at eta = 3 and eta = 7 and
 * compared against the submitted cbd3 / cbd7 (the F-2 claim), and against the
 * Fig. 4 strided reading (the F-2 falsification candidate, section 6).
 *
 * Built WITHOUT -DSPEC_F2, so cbd3/cbd7 here are the submitted composites.
 *
 *   ./selfcheck [trials]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "params.h"
#include "poly.h"
#include "sample.h"

#define NMAX PARAM_N

static uint64_t st;
static uint8_t rnd8(void)
{
	st ^= st << 13; st ^= st >> 7; st ^= st << 17;
	return (uint8_t)(st >> 24);
}

/* number of bytes Algorithm 11 consumes for (n, eta): ceil(n*eta/4) */
static size_t alg11_bytes(int n, int eta) { return (size_t)((n * (long)eta + 3) / 4); }

typedef void (*cbdfn)(int16_t *, const uint8_t *);
static void w_cbd1(int16_t *r, const uint8_t *b) { cbd1(r, b); }
static void w_cbd2(int16_t *r, const uint8_t *b) { cbd2(r, b); }
static void w_cbd3(int16_t *r, const uint8_t *b) { cbd3(r, b); }
static void w_cbd4(int16_t *r, const uint8_t *b) { cbd4(r, b); }
static void w_cbd7(int16_t *r, const uint8_t *b) { cbd7(r, b); }

struct res { unsigned long tot, diffc, difftr; int maxabs; long first; };

static void run(const char *tag, cbdfn code, int eta, unsigned long trials,
                void (*lit)(int16_t *, const uint8_t *, int, int), struct res *R)
{
	static uint8_t buf[4 * NMAX + 64];
	static int16_t a[NMAX], b[NMAX];
	size_t nb = alg11_bytes(PARAM_N, eta);
	memset(R, 0, sizeof *R);
	R->first = -1;
	for (unsigned long t = 0; t < trials; t++) {
		for (size_t i = 0; i < nb; i++) buf[i] = rnd8();
		code(a, buf);
		lit(b, buf, eta, PARAM_N);
		int tdiff = 0;
		for (int i = 0; i < PARAM_N; i++) {
			R->tot++;
			if (a[i] != b[i]) {
				R->diffc++;
				tdiff = 1;
				int d = a[i] - b[i]; if (d < 0) d = -d;
				if (d > R->maxabs) R->maxabs = d;
				if (R->first < 0) R->first = i;
			}
		}
		if (tdiff) R->difftr++;
	}
	printf("  %-38s trials=%lu coeffs=%lu differ=%lu (%.4f%%) maxabsdiff=%d firstidx=%ld\n",
	       tag, trials, R->tot, R->diffc,
	       R->tot ? 100.0 * (double)R->diffc / (double)R->tot : 0.0, R->maxabs, R->first);
}

int main(int argc, char **argv)
{
	unsigned long trials = (argc > 1) ? strtoul(argv[1], NULL, 10) : 1000;
	st = 0x9e3779b97f4a7c15ULL ^ ((uint64_t)PARAM_N << 32) ^ (uint64_t)PARAM_Q;
	for (int i = 0; i < 64; i++) (void)rnd8();

	printf("[selfcheck] PARAMS=%d n=%d q=%d NTT_DIM=%d\n", PARAMS, PARAM_N, PARAM_Q, NTT_DIM);
	printf(" -- step 1: my Algorithm-11 transcription vs the submitted cbd1/cbd2/cbd4\n");
	printf("    (these MUST be 0 differ: they are the correctness proof of cbd_eta_alg11)\n");
	struct res r1, r2, r4, r3, r7, f3, f7, f1, f2, f4;
	run("alg11(eta=1) vs submitted cbd1", w_cbd1, 1, trials, cbd_eta_alg11, &r1);
	run("alg11(eta=2) vs submitted cbd2", w_cbd2, 2, trials, cbd_eta_alg11, &r2);
	run("alg11(eta=4) vs submitted cbd4", w_cbd4, 4, trials, cbd_eta_alg11, &r4);

	printf(" -- step 2: the F-2 claim: submitted cbd3/cbd7 vs Algorithm 11\n");
	run("alg11(eta=3) vs submitted cbd3", w_cbd3, 3, trials, cbd_eta_alg11, &r3);
	run("alg11(eta=7) vs submitted cbd7", w_cbd7, 7, trials, cbd_eta_alg11, &r7);

	printf(" -- step 3 (section 6 falsification): Fig.4 strided reading vs the submitted code\n");
	run("fig4-rowmajor(eta=1) vs cbd1", w_cbd1, 1, trials, cbd_eta_fig4, &f1);
	run("fig4-rowmajor(eta=2) vs cbd2", w_cbd2, 2, trials, cbd_eta_fig4, &f2);
	run("fig4-rowmajor(eta=4) vs cbd4", w_cbd4, 4, trials, cbd_eta_fig4, &f4);
	run("fig4-rowmajor(eta=3) vs cbd3", w_cbd3, 3, trials, cbd_eta_fig4, &f3);
	run("fig4-rowmajor(eta=7) vs cbd7", w_cbd7, 7, trials, cbd_eta_fig4, &f7);
	struct res p1, p2, p4, p3, p7;
	run("fig4-exact/Pt2noise(eta=1) vs cbd1", w_cbd1, 1, trials, cbd_eta_pt2noise, &p1);
	run("fig4-exact/Pt2noise(eta=2) vs cbd2", w_cbd2, 2, trials, cbd_eta_pt2noise, &p2);
	run("fig4-exact/Pt2noise(eta=4) vs cbd4", w_cbd4, 4, trials, cbd_eta_pt2noise, &p4);
	run("fig4-exact/Pt2noise(eta=3) vs cbd3", w_cbd3, 3, trials, cbd_eta_pt2noise, &p3);
	run("fig4-exact/Pt2noise(eta=7) vs cbd7", w_cbd7, 7, trials, cbd_eta_pt2noise, &p7);

	/* single-buffer illustration, first 8 coefficients, eta=3 */
	{
		static uint8_t buf[4 * NMAX + 64];
		static int16_t a[NMAX], b[NMAX], c[NMAX];
		for (size_t i = 0; i < alg11_bytes(PARAM_N, 3); i++) buf[i] = (uint8_t)(0x11 * (i + 1) + i * i);
		cbd3(a, buf); cbd_eta_alg11(b, buf, 3, PARAM_N); cbd_eta_fig4(c, buf, 3, PARAM_N);
		printf("    eta=3 first 8 coeffs  code:");
		for (int i = 0; i < 8; i++) printf(" %+d", a[i]);
		printf("\n                          alg11:");
		for (int i = 0; i < 8; i++) printf(" %+d", b[i]);
		printf("\n                          fig4 :");
		for (int i = 0; i < 8; i++) printf(" %+d", c[i]);
		printf("\n");
	}

	int ok = (r1.diffc == 0 && r2.diffc == 0 && r4.diffc == 0);
	printf("[selfcheck] SELFCHECK_ETA124=%s  F2_CONFIRMED=%s  FIG4_EXPLAINS_CODE=%s\n",
	       ok ? "PASS" : "FAIL",
	       (r3.diffc && r7.diffc) ? "yes" : "no",
	       (f3.diffc == 0 && f7.diffc == 0) ? "yes" : "no");
	printf("[selfcheck] PT2NOISE_LAYOUT_EXPLAINS_CODE=%s (eta=3,7: %lu / %lu differing coeffs)\n",
	       (p3.diffc == 0 && p7.diffc == 0) ? "yes" : "no", p3.diffc, p7.diffc);
	return ok ? 0 : 1;
}
