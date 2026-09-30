import math, json, sys
import nev_dfr_decoders as M
P_STAR = {"C1":-170,"C2":-173,"C3":-175,"R1":-145,"R2":-170,"R3":-160,"D1":-147,"D2":-229,"D3":-313}
T7_DFR = {"C1":-161,"C2":-162,"C3":-163,"R1":-134,"R2":-158,"R3":-147,"D1":-136,"D2":-217,"D3":-301}
rows=[]
for nm in M.ORDER:
    a  = M.run_set(nm,"A"); a0 = M.run_set(nm,"A0"); b = M.run_set(nm,"B")
    b0 = M.run_set(nm,"B",parity=0)
    st = M.run_set(nm,"B",star=True) if M.SETS[nm][1]==769 else None
    rows.append(dict(set=nm,A=a,A0=a0,B=b,B0=b0,ST=st))
    print(nm,"done",file=sys.stderr)
json.dump([{k:(v if not isinstance(v,dict) else v) for k,v in r.items()} for r in rows],
          open("results.json","w"),indent=1,default=str)

print("\n=== TABLE 1 : model A (reference model, reproduces build/est/nev_dfr.out) ===")
print(f"{'set':>4} {'spec blk':>10} {'spec DFR':>10} {'code blk':>10} {'code DFR':>10} {'delta':>8}")
for r in rows:
    a=r['A']; print(f"{r['set']:>4} {a['spec_block']:10.3f} {a['spec_dfr']:10.3f} "
                    f"{a['code_block']:10.3f} {a['code_dfr']:10.3f} {a['delta_bits']:+8.3f}")

print("\n=== TABLE 2 : model B (exact e', worst-case message M=1^l) ===")
print(f"{'set':>4} {'spec DFR UB':>12} {'code DFR UB':>12} {'delta':>8} {'LB spec':>9} {'LB code':>9} "
      f"{'T2 claim':>9} {'T7 DFR':>8} {'T7 p*':>7} {'p*-LB':>7}")
for r in rows:
    b=r['B']; nm=r['set']
    print(f"{nm:>4} {b['spec_dfr']:12.3f} {b['code_dfr']:12.3f} {b['delta_bits']:+8.3f} "
          f"{b['spec_lb']:9.3f} {b['code_lb']:9.3f} {M.CLAIM[nm]:9d} {T7_DFR[nm]:8d} "
          f"{P_STAR[nm]:7d} {P_STAR[nm]-b['spec_lb']:+7.2f}")

print("\n=== TABLE 3 : diagnostics ===")
print("%4s %4s %12s %21s %13s %19s %13s" % ("set","eps","A0 spec DFR","cost of eprime WC",
      "slope b/unit","eff. shift (units)","B0 (M=0) DFR"))
for r in rows:
    a,a0,b,b0=r['A'],r['A0'],r['B'],r['B0']
    cost=a0['spec_dfr']-a['spec_dfr']   # negative-log bits gained by dropping the shift
    slope=(-cost)/a['eps'] if a['eps'] else float('nan')
    print(f"{r['set']:>4} {a['eps']:4d} {a0['spec_dfr']:12.3f} {cost:21.3f} {slope:13.4f} "
          f"{(-b['delta_bits'])/slope:19.3f} {b0['spec_dfr']:13.3f}")

print("\n=== TABLE 4 : compressed C* sets (rounded T*_{1/3}), model B, all 16 y ===")
for r in rows:
    if r['ST'] is None: continue
    s=r['ST']; b=r['B']
    print(f"{r['set']+'*':>4} spec DFR UB {s['spec_dfr']:9.3f}  code {s['code_dfr']:9.3f}  "
          f"delta {s['delta_bits']:+.3f}  LB {s['spec_lb']:9.3f}  (uncompressed: {b['spec_dfr']:.3f})")
