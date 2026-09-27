
/* ===== Public-key-only forger (analysis code, not part of submission) ===== */
int origami_forge_pk_only(uint8_t *sig, const uint8_t *pk,
                          const uint8_t *digest, size_t len_digest,
                          const uint8_t salt[BYTES_SALT], uint32_t rnd) {
    ph_expanded_PK pkx;
    gf_t target[ORIGAMI_M], y[ORIGAMI_N], pub[ORIGAMI_N];
    gf_t A[ORIGAMI_MAX_FLAT_M * ORIGAMI_MAX_FLAT_O], W[ORIGAMI_MAX_FLAT_O];
    residual_schedule_t rs;
    uint8_t dummy[SEED_LENGTH_PRIVATE] = {0};
    if (ORIGAMI_NAMESPACE(pk_expand)(&pkx, pk) != 0) return -1;
    hash_to_field(target, digest, len_digest, salt);
    residual_schedule_init(&rs, pkx.pk_seed);
    memset(y, 0, sizeof(y));
    for (int zone = 0; zone < ORIGAMI_TOTAL_ZONES; zone++) {
        const zone_info_t *zn = &g_zones[zone];
        const int non_oil_count = zn->n_offset + zn->flat_v;
        const int oil_start = non_oil_count;
        const int64_t zone_base = eligible_affine_positions_before_zone(zone);
        int ok = 0;
        for (int att = 0; att < 256 && !ok; att++) {
            /* attacker picks arbitrary vinegar values for this zone */
            for (int i = 0; i < zn->flat_v; i++)
                y[zn->n_offset + i] = (gf_t)((rnd * 2654435761u + (uint32_t)(i * 97 + att * 31 + zone * 7)) >> 7) & 0xF;
            memset(A, 0, sizeof(A));
            for (int eq = 0; eq < zn->flat_m; eq++) {
                gf_stream_t gs;
                const int64_t eq_base = zone_base + (int64_t)eq * non_oil_count * zn->flat_o;
                public_affine_stream_for_eq(&gs, pkx.pk_seed, zn->m_offset + eq);
                for (int non = 0; non < non_oil_count; non++)
                    for (int o = 0; o < zn->flat_o; o++) {
                        gf_t c = gf_stream_next(&gs);
                        long r = residual_rank_from_index(&rs, eq_base + (int64_t)non * zn->flat_o + o);
                        if (r >= 0) c = pkx.R_coeffs[r];
                        gf_set_add(&A[eq * zn->flat_o + o], gf_mult(c, y[non]));
                    }
            }
            if (solve_rect_random(W, A, target + zn->m_offset, zn->flat_m, zn->flat_o,
                                  dummy, sizeof dummy, zone, att, digest, len_digest, salt) == 0) {
                for (int o = 0; o < zn->flat_o; o++) y[oil_start + o] = W[o];
                ok = 1;
            }
        }
        if (!ok) { ORIGAMI_NAMESPACE(pk_free)(&pkx); return -2; }
    }
    for (int i = 0; i < ORIGAMI_N; i++) pub[pkx.secret_to_public[i]] = y[i];
    compress_gf(sig, pub, ORIGAMI_N);
    memcpy(sig + BYTES_GF(ORIGAMI_N), salt, BYTES_SALT);
    ORIGAMI_NAMESPACE(pk_free)(&pkx);
    return 0;
}
