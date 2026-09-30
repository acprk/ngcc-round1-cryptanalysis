# Grinding-counter statistics over the shipped KAT signatures.
#
# Why this is evidence: if the signer really enforced the spec's wgrind zero bits
# (Table 5.3), the grinding counter ctr would be geometric with mean ~2^wgrind and
# match the spec's own Table 5.5 "expected number of iterations". If it enforces only
# wgrind-2 bits, the mean drops by a factor of 4. We read ctr straight out of each
# shipped signature and compare against both predictions.
#
# Usage:  REF=/path/to/SYDO_submission python3 kat_ctr.py
#         (REF must contain Test_Vectors/KAT_SIG_sydo_<set>.txt; defaults to $PWD/ref)
import os, re, sys

# Spec Table 5.3 grinding parameter, and Table 5.5 expected grinding iterations.
spec_w = {'160s': 8, '160f': 2, '256s': 5, '256f': 2, '512s': 8, '512f': 2}
table55 = {'160s': 8290.0, '160f': 20.9, '256s': 302.0, '256f': 4.54,
           '512s': 17400.0, '512f': 26.0}

REF = os.environ.get('REF', os.path.join(os.getcwd(), 'ref'))
LAY = os.environ.get('LAYOUTS', 'layouts.txt')

lay = {}
for line in open(LAY):
    parts = line.split()
    if not parts:
        continue
    lay[parts[0][5:]] = dict(kv.split('=') for kv in parts[1:])

for lv, w in spec_w.items():
    if lv not in lay:                  # layouts.txt may cover only the sets that were built
        continue
    L = lay[lv]
    grind_off = int(L['grind_off'])
    total = int(L['total'])
    width = total - grind_off          # 4 bytes in every shipped parameter set
    path = os.path.join(REF, 'Test_Vectors', f'KAT_SIG_sydo_{lv}.txt')
    sigs = re.findall(r'\nSn = ([0-9A-F]+)', open(path).read())
    ctrs = []
    for s in sigs:
        b = bytes.fromhex(s)[:total]
        ctrs.append(int.from_bytes(b[grind_off:grind_off + width], 'little'))
    mean = sum(ctrs) / len(ctrs)
    enforced = int(L['enforced_zero_bits'])
    pred_impl = table55[lv] / 2 ** (w - enforced)   # prediction if only `enforced` bits are ground
    print(f'sydo_{lv}: KAT grinding counters mean={mean:.1f} '
          f'(spec Table 5.5 expects {table55[lv]}, i.e. with {w - enforced} fewer bits '
          f'≈ {pred_impl:.1f}); ctr={ctrs}')
