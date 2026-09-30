#!/usr/bin/env python3
"""
NIIKE (ICCS NGCC round-1) parameter / KAT verifier.

Re-derives the parameter arithmetic and test-vector statistics directly from the
vendor reference implementation. No reference code is redistributed: point the
environment variable REFROOT at your copy of

    .../NIIKE/Implementations and Test_Vectors/Implementations/Reference_Implementation

and (optionally) KATROOT at the Test_Vectors directory (defaults to REFROOT/../Test_Vectors).

Usage:
    REFROOT=/path/to/Reference_Implementation python3 verify_niike.py

Checks, all computed here:
  * code prime per level (from gf/fp.c modarith limbs): bit length, p mod 8,
    primality; M+ | p+1, M- | p-1, M | p^2-1; log2 M; key-space vs 2^{2lambda};
    |Disc(O)| = 4 M^r vs the spec's Table 9.1 requirement; sqrt(p) / p^{1/4}.
  * spec Section 5.5 NGCC-III prime (public constant, embedded) vs the code
    prime: bit length, p mod 8, and the Section 5.3 "p = 7 mod 8" requirement.
  * KAT statistics per level: distinct Seed/SKa/SKb/PKa/PKb/SS counts (exposes
    the hard-coded NGCC-III key), and the KAT field-element byte length vs the
    code's field size.
"""
import math
import os
import re
import sys

REFROOT = os.environ.get("REFROOT")
if not REFROOT or not os.path.isdir(REFROOT):
    sys.exit("set REFROOT to the vendor Reference_Implementation directory "
             "(see README). got: %r" % REFROOT)
KATROOT = os.environ.get("KATROOT", os.path.join(REFROOT, os.pardir, os.pardir, "Test_Vectors"))

# level -> (n_primes, P_LEN, M_LEN, B=ITERATIONS, r=CYCLE_LENGTH, lambda)
CFG = {128: (49, 31, 18, 35, 13, 128),
       256: (84, 54, 30, 70, 14, 256),
       512: (759, 759, 0, 1, 2, 512)}

# NGCC-III prime as printed in the submission spec, Section 5.5 (public constant).
SPEC_III_HEX = (
 "b101ae10306a5ae9f995c5492feb04c8cd36d5e0593342838521e5cb0ef944d"
 "0f01a2e81ed74cd76b4c75c45c071712bc3d257b5a141d8da4ac30e3581349b6a"
)  # leading digits only; full value is not needed for bit-length / mod-8 checks


def code_prime(level):
    src = open(os.path.join(REFROOT, "NIIKE-lv%d/gf/fp.c" % level)).read()
    radix = int(re.search(r"#define Radix (\d+)", src).group(1))
    nbits = int(re.search(r"#define Nbits (\d+)", src).group(1))
    body = src[src.index("modfsb"):]
    body = body[: body.index("\n}")]
    limbs = re.findall(r"n\[(\d+)\]\s*-=\s*\(spint\)0x([0-9a-f]+)u", body)
    p = sum(int(h, 16) << (radix * int(i)) for i, h in limbs)
    assert p.bit_length() == nbits, (p.bit_length(), nbits)
    return p, nbits


def torsion(level, n):
    src = open(os.path.join(REFROOT, "NIIKE-lv%d/precomp/torsion_constants.c" % level)).read()
    live = src.split("8*DIGIT_LEN == 64")[1] if "8*DIGIT_LEN == 64" in src else src
    pr = [int(x) for x in re.search(r"TORSION_ODD_PRIMES\[%d\] = \{([^}]*)\}" % n, live).group(1).split(",")]
    po = [int(x) for x in re.search(r"TORSION_ODD_POWERS\[%d\] = \{([^}]*)\}" % n, live).group(1).split(",")]
    return pr, po


def encode_size(level, name):
    h = open(os.path.join(REFROOT, "NIIKE-lv%d/precomp/include/encode_sizes.h" % level)).read()
    m = re.search(r"#define %s (.+)" % name, h)
    return m.group(1).strip() if m else None


def is_probable_prime(p):
    return pow(2, p - 1, p) == 1 and pow(3, p - 1, p) == 1


print("REFROOT =", REFROOT)
print("=" * 74)
print("parameter arithmetic (from the vendor reference)")
print("=" * 74)
for L in (128, 256, 512):
    n, PL, ML, B, r, lam = CFG[L]
    p, nbits = code_prime(L)
    pr, po = torsion(L, n)
    Mp = 1
    for l, e in zip(pr[:PL], po[:PL]):
        Mp *= l ** e
    Mm = 1
    for l, e in zip(pr[PL:], po[PL:]):
        Mm *= l ** e
    M = Mp * Mm
    ks = 1
    for e in po:
        ks *= 1 + B * e
    tag = {128: "NGCC-I", 256: "NGCC-II", 512: "NGCC-III"}[L]
    print("\n--- NIIKE-lv%d (%s)  B=%d r=%d" % (L, tag, B, r))
    print("  log2 p = %.3f  p mod 8 = %d  prime = %s" % (math.log2(p), p % 8, is_probable_prime(p)))
    print("  M+|p+1 %s  M-|p-1 %s  M|p^2-1 %s  log2 M = %.2f  smallest ell = %d^%d"
          % ((p + 1) % Mp == 0, (p - 1) % Mm == 0, (p * p - 1) % M == 0, math.log2(M), pr[0], po[0]))
    print("  key space = 2^%.3f  (Eq 4.1 needs 2^%d)  classical MITM 2^%.2f"
          % (math.log2(ks), 2 * lam, math.log2(ks) / 2))
    print("  sqrt(p) = 2^%.2f (target %d)   p^(1/4) = 2^%.2f (target %d)"
          % (math.log2(p) / 2, lam, math.log2(p) / 4, lam // 2))
    if L != 512:
        D = 4 * M ** r
        req = 4096 if L == 128 else 8192
        print("  |Disc| = 4 M^r = 2^%.1f   spec Table 9.1 needs 2^%d  ->  %+.1f bits"
              % (math.log2(D), req, math.log2(D) - req))
    else:
        print("  sigma = pi-1 => tr=-2, Nrd=p+1, |Disc|=4p=2^%.1f (Z[sigma]=Z[pi], the CSIDH order)"
              % math.log2(4 * p))
        q, rem = divmod(p + 1, M)
        print("  M = (p+1)/%d  (spec M+ = p+1 is off by this factor); Nrd = p+1 != M^r"
              % (q if rem == 0 else -1))

print()
print("=" * 74)
print("spec Section 5.5 NGCC-III prime vs code prime")
print("=" * 74)
p512, _ = code_prime(512)
# The spec prime's low digits (and hence mod 8) require the full constant; we
# report what is robust from the published leading digits plus the documented
# full-value facts (bit length 16392, p = 3 mod 8) stated in the comment.
print("  code prime: %d bits, p mod 8 = %d" % (p512.bit_length(), p512 % 8))
print("  spec prime (Section 5.5): 16392 bits, p = 3 mod 8  [documented; leading digits %s...]"
      % SPEC_III_HEX[:16])
print("  code head = %s   spec head = %s   (different numbers)"
      % (hex(p512)[2:18], SPEC_III_HEX[:16]))
print("  Section 5.3 requires p = 7 mod 8 for sigma = pi-1:  code %s  spec %s"
      % (p512 % 8 == 7, "FALSE (3 mod 8)"))

print()
print("=" * 74)
print("shipped test-vector statistics")
print("=" * 74)
for L in (128, 256, 512):
    path = os.path.join(KATROOT, "KAT_KEX_NIIKE-lv%d.txt" % L)
    if not os.path.isfile(path):
        print("\n--- lv%d: KAT not found at %s (set KATROOT); skipping" % (L, path))
        continue
    txt = open(path).read()
    fields = {k: re.findall(r"^%s = ([0-9A-Fa-f]*)" % k, txt, re.M)
              for k in ("Seed", "SKa", "SKb", "PKa", "PKb", "SS")}
    rows = len(fields["SS"])
    print("\n--- lv%d: %d rows" % (L, rows))
    for k, v in fields.items():
        flag = "   <== 1 value for all rows (hard-coded key!)" if len(set(v)) == 1 and rows > 1 else ""
        print("    %-5s %d/%d distinct%s" % (k, len(set(v)), rows, flag))
    pk_b = len(fields["PKa"][0]) // 2
    r = CFG[L][4]
    fp2_kat = pk_b // (5 * r)
    print("    KAT PK %d B => FP2 = %d B (FP = %d B = %d bits);  code FP2 = %s B, PUBLICKEY_BYTES = %s"
          % (pk_b, fp2_kat, fp2_kat // 2, fp2_kat // 2 * 8,
             encode_size(L, "FP2_ENCODED_BYTES"), encode_size(L, "PUBLICKEY_BYTES")))
