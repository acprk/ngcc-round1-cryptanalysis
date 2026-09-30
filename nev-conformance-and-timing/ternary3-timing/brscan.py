import re,subprocess,sys,collections
obj=sys.argv[1]
d=subprocess.run(['objdump','-d','--no-show-raw-insn',obj],capture_output=True,text=True).stdout
cur=None; res=collections.OrderedDict(); lines=collections.defaultdict(list)
for ln in d.splitlines():
    m=re.match(r'^[0-9a-f]+ <(.+)>:',ln)
    if m: cur=m.group(1); res[cur]=0; continue
    if cur is None: continue
    m=re.match(r'^\s+[0-9a-f]+:\s+(j[a-z]+)\s',ln)
    if m and m.group(1)!='jmp':
        res[cur]+=1; lines[cur].append(ln.strip())
want=sys.argv[2:] if len(sys.argv)>2 else None
for f,n in res.items():
    if want and not any(w in f for w in want): continue
    print(f"{obj}  {f}: {n} conditional jumps")
    if want:
        for l in lines[f]: print("     ",l)
