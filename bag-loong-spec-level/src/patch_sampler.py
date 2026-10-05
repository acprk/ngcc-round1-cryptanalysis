#!/usr/bin/env python3
"""Repair the BAG-Loong reference support sampler (the kem-03-3 defect) so that the
supports are secret and uniformly random, as BAG-Loong.KeyGen in the specification
requires (Algorithm 1: "Sample error matrices X, Y randomly from S_A^{n x n1}(F_q^m)").

Only the body of sample_support_pair_logical() is replaced; the rank/intersection
table A_{X,Y}, the matrix coefficient sampling, and everything else are untouched.
The replacement mirrors the submission's own unused loong_support_sample_pair()
(src/loong_support.c), but samples through random_logical_elt() so the m-bit logical
layer constraint still holds.

This is the repair the kem-03-3 ePrint (2026/2223, Sec. 5.2) proposes.  The point of
the exercise is that our finding survives it.
"""
import pathlib
import shutil
import sys

OLD = """	/*
	 * The PKE product-noise bound is on products of the sampled supports, not
	 * only on their individual ranks.  Use a low-degree monomial support pool
	 * so the rank/intersection table is obeyed while products remain inside
	 * the decoder's epsilon budget.  Matrix coefficients are still sampled
	 * from the seed-dependent XOF below.
	 */
	(void)reader;
	(void)require_one_in_v2;
	while (pool_size < union_rank) {
		rbc_elt candidate;
		rbc_elt_set_zero(&candidate);
		if (rbc_elt_set_coefficient(&candidate, pool_size, 1U) != 0) {
			free(pool);
			return LOONG_ERR_BAD_LENGTH;
		}
		if (append_independent(pool, &pool_size, union_rank, &candidate) !=
		    LOONG_SUCCESS) {
			free(pool);
			return LOONG_ERR_SAMPLING;
		}
	}
"""

NEW = """	/*
	 * PATCHED (BAG-Loong-attack): spec-faithful secret support sampling.
	 * The archived code used a fixed public monomial pool {1, X, X^2, ...},
	 * which is ngcc.dev kem-03-3.  Here the pool is drawn from the keygen XOF,
	 * exactly as the submission's own loong_support_sample_pair() does, so the
	 * supports are secret.  require_one_in_v2 is now honoured explicitly: the
	 * element 1 is placed first, hence it lands in the g-dimensional
	 * intersection and therefore in Supp(Y), as KeyGen demands.
	 */
	if (require_one_in_v2 && union_rank != 0) {
		rbc_elt one;
		rbc_elt_set_one(&one);
		if (append_independent(pool, &pool_size, union_rank, &one) !=
		    LOONG_SUCCESS) {
			free(pool);
			return LOONG_ERR_CRYPTO_REJECT;
		}
	}
	{
		unsigned int attempts = 0;
		while (pool_size < union_rank &&
		       attempts < LOONG_PKE_SUPPORT_ATTEMPTS) {
			rbc_elt candidate;
			int st;

			attempts++;
			st = random_logical_elt(&candidate, reader);
			if (st != LOONG_SUCCESS) {
				free(pool);
				return st;
			}
			if (rbc_elt_is_zero(&candidate)) {
				continue;
			}
			(void)append_independent(pool, &pool_size, union_rank,
			                         &candidate);
		}
		if (pool_size != union_rank) {
			free(pool);
			return LOONG_ERR_SAMPLING;
		}
	}
"""


E_OLD = """	status = sample_from_support(e, LOONG_PKE_C2_SIZE, support_re,
	                             LOONG_AR_00, 0, &reader);"""

E_NEW = """	/*
	 * PATCHED (BAG-Loong-attack, variant B): Enc samples E from Supp(R1) in the
	 * archived code, but the specification (Sec. 1.2, "we do not consider E
	 * since Supp(E) = Supp(R2)") puts E on the support of R2.  With this line
	 * the error support is contained in V2.VY + V1.VX, which is the space the
	 * spec's own correctness bound is derived from.
	 */
	status = sample_from_support(e, LOONG_PKE_C2_SIZE, support_r2,
	                             LOONG_AR_11, 0, &reader);"""


def main() -> int:
    src_root = pathlib.Path(sys.argv[1])
    dst_root = pathlib.Path(sys.argv[2])
    variant = sys.argv[3] if len(sys.argv) > 3 else "B"
    dst_root.mkdir(parents=True, exist_ok=True)
    for name in ("128", "256", "384", "512"):
        src = src_root / f"Loong-Block-ms-{name}"
        dst = dst_root / name
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        pke = dst / "src" / "loong_pke.c"
        text = pke.read_text()
        if text.count(OLD) != 1:
            print(f"FAIL {name}: expected exactly one match, got {text.count(OLD)}")
            return 1
        text = text.replace(OLD, NEW)
        if variant == "B":
            if text.count(E_OLD) != 1:
                print(f"FAIL {name}: E-support anchor not unique")
                return 1
            text = text.replace(E_OLD, E_NEW)
        pke.write_text(text)
        print(f"patched {dst} (variant {variant})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
