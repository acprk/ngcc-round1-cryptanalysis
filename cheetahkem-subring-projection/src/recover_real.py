import json, time, sys
from fpylll import IntegerMatrix, LLL, GSO
sys.path.insert(0, "/home/luck/xzy/0930project/pkc/build/subring_attack/g6k_big")
from g6k import Siever, SieverParams
from g6k.algorithms.bkz import pump_n_jump_bkz_tour
from g6k.utils.stats import dummy_tracer

D = json.load(open("cheetah128_proj.json"))
q, n = D["q"], D["n"]; A = D["A"]; b = D["b"]
s_score = D["s_score"]
m = n
d = m + n + 1
print("[+] real Cheetah128 projected LWE: n=%d m=%d q=%d embed-dim=%d" % (n, m, q, d), flush=True)

M = IntegerMatrix(d, d)
for i in range(m):
    M[i, i] = q
for i in range(n):
    for j in range(m):
        M[m + i, j] = A[j][i]
    M[m + i, m + i] = 1
for j in range(m):
    M[d - 1, j] = b[j]
M[d - 1, d - 1] = 1

t0 = time.time()
LLL.reduction(M)   # fpylll wrapper: escalates precision, does not hit the babai loop
print("[+] LLL(wrapper) done (%.1fs)" % (time.time() - t0), flush=True)

def check(g):
    B = g.M.B
    for r in range(d):
        row = [B[r, k] for k in range(d)]
        if abs(row[d - 1]) == 1:
            sign = -row[d - 1]
            cand_s = [sign * row[m + k] for k in range(n)]
            if cand_s == s_score or [-x for x in cand_s] == s_score:
                return True
    return False

# exact integer-Gram + double GSO; the per-tour babai loop is caught (patched bkz._safe_lll),
# so double stays fast (48-thread sieve) instead of escalating to slow mpfr.
Mg = GSO.Mat(M, float_type="double", flags=GSO.INT_GRAM,
             U=IntegerMatrix.identity(d, int_type=M.int_type),
             UinvT=IntegerMatrix.identity(d, int_type=M.int_type))
Mg.update_gso()
g = Siever(Mg, SieverParams(threads=48))
print("[+] Siever ready (INT_GRAM+double, threads=48, max_sieving_dim=%d)" % g.max_sieving_dim, flush=True)

if check(g):
    print("[***] recovered after LLL"); sys.exit(0)

for beta in [50, 58, 64, 70, 76, 81, 85, 89]:
    tb = time.time()
    pump_n_jump_bkz_tour(g, dummy_tracer, beta, jump=1, pump_params={"down_sieve": True})
    dt = time.time() - tb
    hit = check(g)
    print("[beta=%d] tour %.1fs recovered=%s (total %.1fs)" % (beta, dt, hit, time.time() - t0), flush=True)
    if hit:
        print("[***] REAL-KEY psi(s) RECOVERED at beta=%d wall=%.1fs" % (beta, time.time() - t0), flush=True)
        sys.exit(0)
print("[---] not recovered up to beta=89", flush=True)
