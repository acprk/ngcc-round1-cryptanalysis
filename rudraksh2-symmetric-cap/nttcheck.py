#!/usr/bin/env python3
# The Rudraksh2 spec (Polynomial multiplication, p.5) states: "For NTT, the modulus
# q needs to be a prime number with the primitive 2n-th root-of-unity in the prime
# field Z_q", and Eq (1)/(2) use zeta = a primitive 2n-th root. Z_q^* is cyclic of
# order q-1, so an element of order 2n (a primitive 2n-th root) exists IFF 2n | q-1.
#
# Result: every -I set satisfies this; every -II set (q=4001) does NOT, at any of
# its degrees. So the -II sets contradict the spec's own NTT requirement — they
# cannot be multiplied by the full negacyclic NTT the spec defines (only an
# incomplete NTT + base-case multiplication the spec does not describe would work).
# This is consistent with the submission shipping no -II implementation.
def v2(m):
    k = 0
    while m % 2 == 0:
        m //= 2; k += 1
    return k

def has_primitive_2nth_root(n, q):
    # Z_q^* cyclic of order q-1 (q prime) => element of order 2n exists iff 2n | q-1.
    if (q - 1) % (2 * n) != 0:
        return False, None
    # exhibit one: take a generator power. Find a generator g, then g^((q-1)/2n).
    def order(a):
        o, x = 1, a % q
        while x != 1:
            x = x * a % q; o += 1
        return o
    for g in range(2, q):
        if order(g) == q - 1:
            root = pow(g, (q - 1) // (2 * n), q)
            return True, root
    return True, None

SETS = [("128-I", 64, 3329), ("256-I", 128, 3329), ("512-I", 256, 7681),
        ("128-II", 64, 4001), ("256-II", 128, 4001), ("512-II", 256, 4001)]

print("spec requires a primitive 2n-th root of unity mod q for the negacyclic NTT (Eq. 1/2)\n")
print(f"{'set':8s} {'n':>4s} {'q':>5s} {'2n':>4s} {'v2(q-1)':>8s}  {'2n | q-1':>9s}  verdict")
bad = []
for name, n, q in SETS:
    ok, root = has_primitive_2nth_root(n, q)
    verdict = f"root={root}" if ok else "NO SUCH ROOT — NTT undefined"
    if not ok:
        bad.append(name)
    print(f"{name:8s} {n:4d} {q:5d} {2*n:4d} {v2(q-1):8d}  {str((q-1)%(2*n)==0):>9s}  {verdict}")
print()
print("q-1 2-adic valuations:  3329-1=2^8*13,  7681-1=2^9*3*5,  4001-1=2^5*5^3 (only 2^5)")
print("=> max negacyclic-NTT degree supported by q=4001 is n=16; the -II sets use n=64/128/256.")
print("BROKEN sets (spec-mandated NTT does not exist):", ", ".join(bad) if bad else "none")
