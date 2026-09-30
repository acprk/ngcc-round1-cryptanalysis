# For every shipped KAT signature: does chall3 satisfy the SPEC grinding condition
# chall3[lambda-wgrind .. lambda-1] == 0 (Table 5.3 wgrind)?  Bit order as in the code
# (LSB-first within bytes, sydo.c delta_has_required_zero_bits).
#
# Usage:  REF=/path/to/SYDO_submission python3 kat_grind.py
#         (REF must contain Test_Vectors/KAT_SIG_sydo_<set>.txt; defaults to $PWD/ref)
import os,re,sys
REF=os.environ.get('REF', os.path.join(os.getcwd(),'ref'))
LAY=os.environ.get('LAYOUTS','layouts.txt')
spec_w={'160s':8,'160f':2,'256s':5,'256f':2,'512s':8,'512f':2}
lay={}
for l in open(LAY):
    if not l.split(): continue
    d=dict(kv.split('=') for kv in l.split()[1:]); lay[l.split()[0][5:]]=d
for lv,w in spec_w.items():
    if lv not in lay: continue          # layouts.txt may cover only the sets that were built
    L=lay[lv]; lam=int(L['lambda']); off=int(L['delta_off']); size=int(L['delta_size']); tot=int(L['total'])
    txt=open(os.path.join(REF,'Test_Vectors',f'KAT_SIG_sydo_{lv}.txt')).read()
    sigs=re.findall(r'\nSn = ([0-9A-F]+)',txt)
    ok=0; hist={}
    for s in sigs:
        b=bytes.fromhex(s)[:tot]; delta=b[off:off+size]
        top=[(delta[i//8]>>(i%8))&1 for i in range(lam-w,lam)]
        ok+= (sum(top)==0)
    print(f'sydo_{lv}: spec wgrind={w}, enforced={L["enforced_zero_bits"]}; KAT sigs={len(sigs)}, '
          f'satisfy spec grinding condition: {ok}/{len(sigs)} (expected by chance 2^-{int(w)-int(L["enforced_zero_bits"])} ≈ {len(sigs)/2**(int(w)-int(L["enforced_zero_bits"])):.1f})')
