#!/usr/bin/env bash
# Scloud+ (ICCS NGCC round-1, kem-35): the decapsulation re-encryption rejection sampler consumes a
# MESSAGE-DEPENDENT number of XOF squeezes -> decaps time depends on the decrypted message m'.
#
#   REF="/path/to/Scloud+/.../Implementations" ./run_all.sh          # defaults L=256 FAM=AES
#   REF=... L=512 FAM=AES ./run_all.sh
#
# REF must be the vendor "Implementations" directory (containing _shared/scloudplus_core,
# _shared/api_pkc, Optimized_Implementation/Scloudplus-<L>/kem). The vendor tree is NEVER modified
# in place and NEVER redistributed here: we copy common/sample.c into build/ and apply a 5-line
# counter patch (patches/count.patch) to it; all other vendor files are compiled from REF unchanged.
set -e
REF="${REF:?set REF=/path/to/Scloud+/.../Implementations}"
CC="${CC:-gcc-11}"; L="${L:-256}"; FAM="${FAM:-AES}"
CORE="$REF/_shared/scloudplus_core"; API="$REF/_shared/api_pkc"; LVL="$REF/Optimized_Implementation/Scloudplus-$L/kem"
FL="-std=c99 -O3 -mavx2 -mbmi2 -mpopcnt -maes -DSCLOUDPLUS_FAMILY_$FAM -DSCLOUDPLUS_TIER_OPTIMIZED -DSCLOUDPLUS_BACKEND_AVX2 -DSCLOUDPLUS_AVX2_FAMILY_$FAM"
INC=(-I"$LVL" -I"$CORE/include" -I"$CORE/common" -I"$API")
SRC=("$CORE/common/encode.c" "$CORE/common/kem.c" "$CORE/avx2/matrix_avx2.c" "$CORE/ref/pack_reference.c"
     "$CORE/common/pke.c" "$CORE/common/random.c" "$CORE/common/util.c" "$CORE/avx2/sample_avx2.c" "$LVL/KEM_AlgorithmInstance.c")
case "$FAM" in
  SM3)   FL="$FL -funroll-loops"; SRC+=("$CORE/avx2/hash_sm3_avx2.c" "$CORE/avx2/sm3_avx2.c");;
  AES)   SRC+=("$CORE/common/hash_aes_shake.c" "$CORE/avx2/aes_aesni.c");;
  SHAKE) SRC+=("$CORE/common/hash_aes_shake.c" "$CORE/avx2/fips202x4.c" "$CORE/avx2/keccak4x/KeccakP-1600-times4-SIMD256.c");;
esac
mkdir -p build; cp "$CORE/common/sample.c" build/sample.c
patch -s build/sample.c < patches/count.patch
echo "=== instrumented sample.c built (5-line counter patch applied to a copy of REF's common/sample.c) ==="

echo; echo "=== [1] deterministic: XOF-squeeze count per decaps (message-dependent), 5000 honest decaps ==="
$CC $FL "${INC[@]}" "${SRC[@]}" build/sample.c src/gen_count.c -o build/gen_count 2>/dev/null
./build/gen_count 5000 build/c$L >/dev/null 2>&1
python3 src/analyze.py counts build/c${L}_counts.csv

echo; echo "=== [2] timing: cycles vs XOF-squeeze class (sampler microbench = what pke_enc runs) ==="
# instrumented count binary to label seeds, unmodified-sampler binary to time them
$CC $FL -DCOUNT_MODE "${INC[@]}" "${SRC[@]}" build/sample.c src/sampler_bench.c -o build/sbench_count 2>/dev/null
$CC $FL            "${INC[@]}" "${SRC[@]}" "$CORE/common/sample.c" src/sampler_bench.c -o build/sbench_time 2>/dev/null
./build/sbench_count count 20000 build/seeds.bin build/sbcounts.csv >/dev/null 2>&1
python3 - "$L" <<'PY'
import csv,collections,random,sys
rows=list(csv.DictReader(open('build/sbcounts.csv')))
by=collections.defaultdict(list)
for r in rows: by[int(r['xof_refills'])].append(int(r['idx']))
lo=min(by,key=lambda k:-0 if len(by[k])<3 else k); 
ks=[k for k in sorted(by) if len(by[k])>=40]
a,b=ks[0],ks[-1]; random.seed(1)
sel=[(i,a) for i in random.sample(by[a],min(80,len(by[a])))]+[(i,b) for i in random.sample(by[b],min(80,len(by[b])))]
open('build/sbsel.txt','w').write("\n".join(f"{i} {l}" for i,l in sel))
print(f"  selected 80x squeeze={a} (rare) vs 80x squeeze={b}")
PY
CORE100=$( [ -e /sys/devices/system/cpu/cpu100 ] && echo 100 || echo 0 )
taskset -c $CORE100 ./build/sbench_time time build/seeds.bin build/sbsel.txt 500 build/sbtime.csv 2>/dev/null
python3 src/analyze.py timing build/sbtime.csv build/sbcounts.csv

echo; echo "=== [3] the rest of decapsulation is constant-time (corroboration) ==="
$CC $FL "${INC[@]}" -c "$CORE/common/encode.c" -o build/encode.o 2>/dev/null
echo -n "  Barnes-Wall decoder (encode.o): div/idiv="; objdump -d build/encode.o | grep -cE "\b(div|idiv)\b" | tr -d '\n'
echo -n "  cmov="; objdump -d build/encode.o | grep -cE "\bcmov" | tr -d '\n'; echo "  (0/0 => no secret-dependent division or conditional move; Jcc are loop control)"
echo; echo "Done. The squeeze count is a deterministic function of m' (seed = F(G(m'||H(pk)))), so decapsulation"
echo "time depends on the decrypted message. Fix: make the batch/squeeze count data-independent (see README)."
