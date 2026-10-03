from math import log2
# generate_random_idx: pos from w-1 down to 0; draw rn uniform 32-bit;
#   value = pos + floor(rn*(len-pos)/2^32)  -> uniform on [pos,len) only up to modular bias
# per-draw TV distance from uniform on a range of size L: rem*(L-rem)/(L*2^32), rem = 2^32 mod L
TWO32=1<<32
def tv_draw(L):
    q,rem = divmod(TWO32,L)
    return rem*(L-rem)/(L*TWO32)
def tv_total(length,w):
    return sum(tv_draw(length-pos) for pos in range(w))
INST={'TRIKE-1':(10301,27,201,128,64),'TRIKE-2':(15581,35,263,128,80),'TRIKE-3':(22003,41,319,192,96),
      'TRIKE-5':(35363,55,429,256,128),'TRIKE-7':(69691,83,659,384,192),'TRIKE-9':(114043,111,877,512,256)}
print(f"{'inst':9} {'key sampler TV':>18} {'error sampler TV':>18}   target")
for k,(r,d,t,lam,q) in INST.items():
    k_tv = 3*tv_total(r,d)      # h0,h1,h2
    e_tv = tv_total(3*r,t)      # error over n=3r
    print(f"{k:9} 2^{log2(k_tv):16.2f} 2^{log2(e_tv):16.2f}   2^-{lam}")
print()
print("DRNG (ICCS SM3_DRNG, drng.h): state V = 55 bytes = 440 bits; C=f(V); so <=440 bits of entropy")
for k,(r,d,t,lam,q) in INST.items():
    key_ent = 3*(__import__('math').lgamma(r+1)-__import__('math').lgamma(d+1)-__import__('math').lgamma(r-d+1))/0.6931471805599453
    print(f"  {k:9} claimed {lam:3d} classical /{q:4d} quantum | true key entropy {key_ent:8.0f} bits, but generator caps at 440 "
          f"-> classical {min(440,lam if lam<440 else 440)} {'*** BELOW CLAIM' if lam>440 else 'ok'}; Grover 220 {'*** BELOW CLAIM' if q>220 else 'ok'}")
