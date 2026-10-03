# OLS of log2(mean work) against log2(T+1) for the TRIKE-5 B=10 sweep; theory: 10 - log2(T+1).
import re, math, sys
d = sys.argv[1] if len(sys.argv) > 1 else 'logs'
xs, ys = [], []
print(" T   n  mean_work  ±se    2^B/(T+1)")
for t in range(6):
    w = [int(x) for x in re.findall(r'after (\d+) re-encs', open(f'{d}/t5_B10_T{t}.log').read())]
    T = 2 ** t; m = sum(w) / len(w); se = (sum((x - m) ** 2 for x in w) / (len(w) - 1)) ** .5 / len(w) ** .5
    print(f"{T:3d} {len(w):3d} {m:9.1f} {se:6.1f} {1024 / (T + 1):9.1f}")
    xs.append(math.log2(T + 1)); ys.append(math.log2(m))
mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
print(f"OLS log2(work) = {my - b * mx:.2f} + ({b:.3f})*log2(T+1)   [theory: 10 - log2(T+1)]")
