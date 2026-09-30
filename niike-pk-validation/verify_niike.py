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

# NGCC-III prime as printed in the submission spec, Section 5.5 (public constant,
# transcribed in full so this script can compute p mod 8 itself).
SPEC_III_HEX = (
    "b101ae10306a5ae9f995c5492feb04c8cd36d5e0593342838521e5cb0ef944d0"
    "f01a2e81ed74cd76b4c75c45c071712bc3d257b5a141d8da4ac30e3581349b6a"
    "cd9eb37c3e21618353687ef936185c36f59227d6b371dfa92e874bd926f1ddaa"
    "5b6e031906918c88372cb4312ed4817b8ce1a0573fba2ba8e6d25a0a50fe8fcb"
    "dad4003e1dea3a0dc5d9c3e0e8fe733381d57198acb2feb395440ac9a5c1dd60"
    "5ad4287962bca911468c028c08d5b8c685820414cbce2e5d8a3d7c30135fd167"
    "b3647429a8056cfd6f259d7db9dc50833b69d81ce3c28b8881d71bdc606b6a00"
    "123a8607c6ce21191353fcbc270613370e3993beed976fa16944fda221defd8e"
    "58235aab286fd26fa893bd07247f447be5d93a4845a2e8999cc5b2545fd65750"
    "82ca06e30c6054adc26e6591c096806af4f1342101772a6a7ef451af0d99c48a"
    "882c9617f352ce8f444ab4b9bed613d03dba0f0abd31ef052c0089f1bdac5cae"
    "b974ef7cc45ad16fd91b5b108de929aced307ca813988e94831f70ea9d1ec159"
    "e9a32806645b0239e9aade3616c52b6afecc56adb3cee2b8c8547dee1255b1ad"
    "a323144d62c31d77c9168577c7e5ba5c88fb4285c74a03ffac3467015c3e0aa5"
    "1810d57d2a73883bc0153cc4278e1c748865bf19f8e68eb1d3e738d1fe9d31e8"
    "247330136de610514d770bdb2d495327b982650a62f66385a7842e4d9607f312"
    "aa8f00e7260e3443439cd3b02e8cabf26e3216555f838f91a4500ae1ffbaa6ee"
    "97c27700808b4357c573ac94e4959a73828a5896968f0b991ed04cb54fac07ea"
    "c52fafc4237cf9d7d643b5c234d07ca69a9e2f5c1e414d5cf93a80412e7086db"
    "a91866272d44dd65a3e60eb7e11898d8c50ea4146aed17d8b1434760b2173363"
    "9ba77c10843036dc92b1c3dd0123030738005797c25b4433bc951c1ab5871674"
    "5555d85055ea24100d979dcdd4664a12b6cda5c8fb6da779e4f73ee589e483ee"
    "57c8f457e1d113f188d91231dcc5d2a652fce3e5520e1ae26151ae11ee822824"
    "7b9d512ca0e7b68c94d00d7c8f2d050b99c3c6901fa3d4695ac0bdede743abc8"
    "9950e5f4f227876c2858440675b2d558b0cd571b6e73bae7e6fb8fac42631e35"
    "788c7c65989ae7e5321c06af81d7f67e31797c6f2cd1b287ad5a3174786f9d6f"
    "f41148622f98c1d61438651b9d9721047436311ea4deb2adef18c978e7d6a42b"
    "5e50d0251e16d1475251ab158268fe5d9f21c86c3efdb037debdee9ac83b23d7"
    "c09204c021e524e19a3c9601c7d7cc818383a787574b535d0d251d15507348fb"
    "2423fe2631e6e852b65cbc5004c05b732444c0a5f07d842c051fa3c016d9eca2"
    "5cb9f754455e5408519d0851eb396bb3ac8c38bf67a67d1c631591c4961e5d72"
    "46264b257b10d6b4e1b6dd9b619a68778eb52e2adb7e959a291a776b221195e9"
    "d845673e67066a5f0017a2b3ab32cb7f4e814e4f79090b7e80c0f8006b20b6d2"
    "76965b481a2e3346b748b92b72fcaee2a6c99e2c557e4815af8b8c45a9aa4c1d"
    "c91a939ca426fe88cbbc3a7f4d1fcb9a8fcdb349fefc89d62110a948a825dc6a"
    "bb5438e0c825e9c898e64bac16c9c886a4e460463f4c12b61289496115b9a45c"
    "5e9e42ead86a0bf5f67a20581da325ec66db575c47c6eefd68c629a42bc1e688"
    "7d483ba3d9de7984d989cb5b3f4c1696848f2c5a67dc03086498a092d261ae1b"
    "d4fc22db2b4a12d13e2d3a46d339f7c7a66cba55ba36abfe2c52672221e06b3d"
    "190809860e90507a5dad0b1712d95a9ba1d40b83ddbfed7e5711df972620e9ad"
    "947ce995153fa8eb05d8f1ee891946d8ce4a71e0882214ffc5bc59ab9b34f391"
    "6a22977fed901f38077550c7ec80e9f594bbcc89b7e932edec2897035384d3b4"
    "9fc3236197af2c32bb6e67532c40c91d1280eb16433744c4d6cec0a45bb512fe"
    "029aeda29e968d7384daa33764ec4e77106c568be1e6d081ef882c60719eb61a"
    "0f8262d5378b9f697e672c5a01fcec12ec0d577e13e842ecf05ca00d12cbba18"
    "e433d42a2d508105247f1c85abd541e4bc542c500aa7efd6f9844ffefffdde83"
    "b16c8c724845040749817bcec4d1fcce463f6ec908daeadff7cf4ded296eb7f4"
    "e3af2c73edf9318f842f3ba7e1f23722001fb9f48241002cbf93ea984a99916c"
    "a93d5bc04fff5b544c6d349999a5bc5ff61344b190fbb45f930a2d4dcb226b3d"
    "4466866cce37e0f24bb46a945ccee60b63c0c4195609346221953df23b1860a6"
    "56dc67cd8792be1ce1f5700aa3bcf063c43ac4fc96cee29c4d3156bf2e567ee2"
    "25036e16f24e763e4eb39a506b66c12b260e50d443b410289bf3ca1d5bd28b04"
    "e58e78b54b11470e004f39b16157ed2b19497ded9c90744fc6ae5e4790e3ee9b"
    "4c2c865c80994cade0348e6b8f18f209ba30277416a9c511378e16ab8ea8f547"
    "3c14e7e4a677133742520b13cd80a52cc37569d32c56cf548b57948a650e97e9"
    "d1dc559854356ae18787b29e99337462c4cf1ef2e9530547b620c6e5d57d8055"
    "9cda2af9972603c316e9b95354c672acb5d16e0dc912eb9d2357b65721da59be"
    "7b9a6d405b04bb179a7ddc0a9d3bc00d69bd6625d4b3834ec409d45ddea6f6eb"
    "c62a6b58652f069a5537a31720d0de153d01a4df07d6222a786f364d37f73e81"
    "e27990ca8c283949ac73a4e6e9eed8b8c0c0baa6ac682aed68a84624ebaa8778"
    "46073080b0b82f0cae8618e518a9848690c3f0eb3efb02f395be6bee50914cee"
    "317da268762ca3df653f1e3f5448742896b795c29b178ca2b281174ac8b35615"
    "f9990dd36054c4c50dcee2fa3d3c43f02430eade3abbd51f6bd2afa0bac93368"
    "ffa4ce4ecd86083595c41e149406afbfedf06dd211cdced1f84998f3035c788e"
    "8b"
)


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
p_spec = int(SPEC_III_HEX, 16)
print("  code prime: %d bits, p mod 8 = %d, prime = %s" % (p512.bit_length(), p512 % 8, is_probable_prime(p512)))
print("  spec prime: %d bits, p mod 8 = %d, prime = %s" % (p_spec.bit_length(), p_spec % 8, is_probable_prime(p_spec)))
print("  spec == code : %s" % (p_spec == p512))
print("  code head = %s   spec head = %s   (different numbers)" % (hex(p512)[2:18], hex(p_spec)[2:18]))
print("  Section 5.3 requires p = 7 mod 8 for sigma = pi-1:  code %s  spec %s"
      % (p512 % 8 == 7, p_spec % 8 == 7))

print()
print("=" * 74)
print("item 2(b): the stack counter `top` at the second assert(top==0)")
print("=" * 74)
# In bundleeval_action_stra (protocols/bundleprotocols.c) the second (E[p-1])
# block does: top=0; push R.Pt; top++;  for(i=P_LEN; i<P_LEN+M_LEN; i++){...};
# assert(top==0). `top`'s value there depends ONLY on the compile-time constants
# P_LEN, M_LEN (no data dependence on field arithmetic), so we can read it off
# the vendor ec_params.h without running the 7.6h action. When the M- loop range
# is empty (M_LEN==0), the loop never runs and `top` is still 1 at the assert.
for L in (128, 256, 512):
    ec = open(os.path.join(REFROOT, "NIIKE-lv%d/precomp/include/ec_params.h" % L)).read()
    P_LEN = int(re.search(r"#define P_LEN (\d+)", ec).group(1))
    M_LEN = int(re.search(r"#define M_LEN (\d+)", ec).group(1))
    top_at_assert = 1 if M_LEN == 0 else 0   # the M- loop pops back to 0 iff it runs
    verdict = "assert PASSES" if top_at_assert == 0 else "assert FAILS -> SIGABRT in the default (asserts-on) build"
    print("  lv%-3d P_LEN=%-4d M_LEN=%-3d  top at assert(top==0) = %d  ->  %s"
          % (L, P_LEN, M_LEN, top_at_assert, verdict))

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
