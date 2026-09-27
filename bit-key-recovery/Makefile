# Build the BiT key-recovery attack against the reference implementation.
#
#   make REF=/path/to/Reference_Implementation/BiT-128
#
# REF must point at a BiT-128 reference-implementation source directory. The
# attack links directly against the unmodified scheme sources (keygen, signing,
# verification, packing, sampler, NTT, ...).
#
# Pipeline (see run_all.sh):
#   gen_fixed -> victim honest signatures + pk.bin/key.bin (key.bin scoring only)
#   gen_cal   -> attacker's OWN calibration key signatures + calkey.bin
#   est2      -> bilinear estimator -> acc2_victim.bin / acc2_cal.bin
#   deconv.py -> fit the bias kernel on the cal key, deconvolve victim -> s0_rec.bin
#   forge     -> public-relation finisher + forgery vs the unmodified verifier

REF ?= ./ref/BiT-128
CC  ?= gcc
CFLAGS ?= -O2 -no-pie -std=gnu11 -I$(REF)
LDLIBS ?=

# reference .c except the KAT driver
REFSRC := $(filter-out %/KAT_SIG.c, $(wildcard $(REF)/*.c))

BINS = gen_fixed gen_cal est2 forge

all: $(BINS)

gen_fixed: src/gen_fixed.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
gen_cal: src/gen_cal.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)
est2: src/est2.c
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)
forge: src/forge.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(BINS) *.bin

.PHONY: all clean
