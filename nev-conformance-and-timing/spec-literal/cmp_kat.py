#!/usr/bin/env python3
"""Compare the generated KAT vectors of each spec-literal variant against the
submitted reference-code vectors (variant `base`), and check `base` itself
against src/NEV/Test_Vectors/*_ICCS.txt.

Reports, per (parameter set, backend, variant): which of PK/SK/CT/SS differ, over
how many of the 10 KAT counts, and the byte offset of the first difference in
Count = 0 (offset into the raw field, not into the hex text)."""
import os, re, sys

# ROOT = this package's working directory (where run_kat.sh wrote kat/<variant>/...);
# TV   = the submission's Test_Vectors directory (NEV/Test_Vectors), supplied by the
#        caller via the TV environment variable. Neither is bundled; nothing under TV
#        is copied into this repository (the KAT vectors are only read for comparison).
ROOT = os.environ.get("ROOT", os.path.dirname(os.path.abspath(__file__)))
TV = os.environ.get("TV")
if not TV or not os.path.isdir(TV):
    sys.exit("set TV=<submission>/NEV/Test_Vectors (the submitted *_ICCS.txt live there)")
NAME = {1: "512_769_C", 2: "1024_769_C", 3: "2048_769_C",
        4: "512_1409", 5: "1024_1409", 6: "2048_1409",
        7: "512_3329", 8: "1024_3329", 9: "2048_3329",
        10: "512_769", 11: "1024_769", 12: "2048_769"}
SETNAME = {1: "C1*", 2: "C2*", 3: "C3*", 4: "R1", 5: "R2", 6: "R3",
           7: "D1", 8: "D2", 9: "D3", 10: "C1", 11: "C2", 12: "C3"}
VARIANTS = ["F1", "F2", "F3", "F123"]
FIELDS = ["PK", "SK", "CT", "SS", "Seed"]


def parse(path):
    recs, cur = [], {}
    for line in open(path):
        line = line.strip()
        if line.startswith("Count ="):
            if cur:
                recs.append(cur)
            cur = {}
        m = re.match(r"^(Seed|PK|SK|CT|SS) = ([0-9A-Fa-f]*)$", line)
        if m:
            cur[m.group(1)] = bytes.fromhex(m.group(2))
    if cur:
        recs.append(cur)
    return recs


def katfile(variant, p, be):
    return f"{ROOT}/kat/{variant}/{p}_{be}/output/KAT_KEM_NEV_{NAME[p]}_{be}.txt"


def cmp_recs(a, b):
    out = {}
    assert len(a) == len(b) == 10, (len(a), len(b))
    for f in FIELDS:
        ndiff, first = 0, None
        for i, (ra, rb) in enumerate(zip(a, b)):
            xa, xb = ra[f], rb[f]
            if xa != xb:
                ndiff += 1
                if first is None:
                    off = next(k for k in range(min(len(xa), len(xb))) if xa[k] != xb[k])
                    first = (i, off, xa[off], xb[off])
        out[f] = (ndiff, first)
    return out


def main():
    print("=" * 100)
    print("A. sanity: variant `base` (my copied tree, no -DSPEC_*) vs the SUBMITTED Test_Vectors")
    print("=" * 100)
    allok = True
    for p in range(1, 13):
        sub = f"{TV}/KAT_KEM_NEV_{NAME[p]}_ICCS.txt"
        gen = katfile("base", p, "ICCS")
        a, b = open(sub, "rb").read(), open(gen, "rb").read()
        ok = a == b
        allok &= ok
        print(f"  PARAMS={p:<2} {SETNAME[p]:<4} {NAME[p]:<12} ICCS  "
              f"{'BYTE-IDENTICAL' if ok else 'MISMATCH'}")
    print(f"  => base reproduces 12/12 submitted ICCS vectors: {allok}")

    print()
    print("=" * 100)
    print("B. spec-literal variants vs `base`  (same KAT seeds, same harness)")
    print("   cells: fields that differ, with (#counts of 10) ; '-' = byte-identical to submitted code")
    print("=" * 100)
    hdr = f"{'PARAMS':<7}{'set':<5}{'n':<6}{'q':<6}{'be':<6}" + "".join(f"{v:<26}" for v in VARIANTS)
    print(hdr)
    rows = []
    for p in range(1, 13):
        n, q = NAME[p].split("_")[0], NAME[p].split("_")[1]
        for be in ["ICCS", "SHA3"]:
            base = parse(katfile("base", p, be))
            cells, detail = [], {}
            for v in VARIANTS:
                other = parse(katfile(v, p, be))
                d = cmp_recs(base, other)
                assert d["Seed"][0] == 0, "KAT seeds differ -- harness not comparable"
                changed = [f for f in ["PK", "SK", "CT", "SS"] if d[f][0]]
                if not changed:
                    cells.append("-")
                else:
                    cells.append(",".join(f"{f}({d[f][0]}/10)" for f in changed))
                detail[v] = d
            print(f"{p:<7}{SETNAME[p]:<5}{n:<6}{q:<6}{be:<6}" + "".join(f"{c:<26}" for c in cells))
            rows.append((p, be, detail))

    print()
    print("=" * 100)
    print("C. first differing byte in Count = 0 (field offset, base value -> variant value)")
    print("=" * 100)
    for p, be, detail in rows:
        for v in VARIANTS:
            for f in ["PK", "SK", "CT", "SS"]:
                nd, first = detail[v][f]
                if first:
                    i, off, xa, xb = first
                    print(f"  PARAMS={p:<2} {SETNAME[p]:<4} {be:<5} {v:<5} {f:<3} "
                          f"count={i} offset={off:<5} 0x{xa:02X} -> 0x{xb:02X}")
    print()
    print("=" * 100)
    print("D. cross-variant consistency: is F123 == (F1 then F2 then F3) on the fields each touches?")
    print("=" * 100)
    for p in range(1, 13):
        for be in ["ICCS", "SHA3"]:
            b = parse(katfile("base", p, be))
            f2 = parse(katfile("F2", p, be))
            f3 = parse(katfile("F3", p, be))
            f123 = parse(katfile("F123", p, be))
            eq23 = all(f123[i]["PK"] == f3[i]["PK"] for i in range(10))
            eqf2 = all(f123[i]["PK"] == f2[i]["PK"] for i in range(10))
            print(f"  PARAMS={p:<2} {be:<5} F123.PK==F3.PK:{str(eq23):<6} F123.PK==F2.PK:{str(eqf2):<6} "
                  f"F2.PK==base:{str(all(f2[i]['PK'] == b[i]['PK'] for i in range(10))):<6} "
                  f"F3.PK==base:{str(all(f3[i]['PK'] == b[i]['PK'] for i in range(10))):<6}")


main()
