import csv,sys,collections,statistics as st,math
def counts(f):
    rows=list(csv.DictReader(open(f)))
    b=[int(r['batches']) for r in rows]; s=[int(r['xof_refills']) for r in rows]
    print(f"  decaps={len(rows)}  batches: min={min(b)} max={max(b)} mode={st.mode(b)} distinct={len(set(b))}")
    print(f"                    XOF squeezes: {dict(sorted(collections.Counter(s).items()))}")
    print(f"  => the re-encryption sampler consumes a MESSAGE-DEPENDENT number of XOF squeezes/batches.")
def timing(tf,cf):
    tc={int(r['idx']):(int(r['batches']),int(r['xof_refills'])) for r in csv.DictReader(open(cf))}
    per=collections.defaultdict(list)
    for r in csv.DictReader(open(tf)): per[int(r['idx'])].append(int(r['cycles']))
    seeds=[(tc[i][0],tc[i][1],st.median(cy)) for i,cy in per.items()]
    reps=len(next(iter(per.values())))
    sq=sorted(set(s for _,s,_ in seeds))
    if len(sq)<2: print("  only one squeeze class in selection"); return
    lo,hi=sq[0],sq[-1]
    A=[y for _,s,y in seeds if s==lo]; B=[y for _,s,y in seeds if s==hi]
    gap=st.mean(B)-st.mean(A)
    t=gap/math.sqrt(st.pvariance(A)/len(A)+st.pvariance(B)/len(B))
    db=st.mean([b for b,s,_ in seeds if s==hi])-st.mean([b for b,s,_ in seeds if s==lo])
    # per-batch from WITHIN the populous (hi) class, varying batches -> no squeeze confound
    within=collections.defaultdict(list)
    for b,s,y in seeds:
        if s==hi: within[b].append(y)
    xb=sorted(k for k in within if len(within[k])>=3); 
    perbatch=float('nan')
    if len(xb)>=2:
        xs=xb; ys=[st.mean(within[b]) for b in xb]; n=len(xs); mx=sum(xs)/n; my=sum(ys)/n
        perbatch=sum((x-mx)*(y-my) for x,y in zip(xs,ys))/sum((x-mx)**2 for x in xs)
    persq=gap-(perbatch*db if perbatch==perbatch else 0)
    print(f"  seeds timed: {len(seeds)} (per-seed median of {reps} reps), squeeze classes {lo} vs {hi}")
    print(f"  ROBUST observable: class gap squeeze{hi}-squeeze{lo} = {gap:,.0f} cycles (Welch t = {t:.1f})")
    print(f"     (absolute magnitude is host-load dependent; the gap being significantly != 0, with a null control, is the invariant)")
    print(f"  well-conditioned split (per-batch from WITHIN the squeeze={hi} class, no confound):")
    print(f"     per batch       ~ {perbatch:,.0f} cycles")
    print(f"     per XOF squeeze ~ {persq:,.0f} cycles  (= gap - per_batch * {db:.2f} batches)")
    print(f"  NOTE: the {gap:,.0f} class gap is NOT the per-squeeze cost; it bundles 1 squeeze + {db:.2f} extra batches.")
if __name__=='__main__':
    if sys.argv[1]=='counts': counts(sys.argv[2])
    else: timing(sys.argv[2],sys.argv[3])
