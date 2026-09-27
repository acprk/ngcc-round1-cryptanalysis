# Build the Shuttle key-recovery attack against the reference implementation.
#
#   make MODE=128 REF=/path/to/Reference_Implementation/SHUTTLE-128
#
# REF must point at a Shuttle reference-implementation source directory for the
# matching MODE (128 / 256 / 512).  The attack links directly against the
# unmodified scheme sources (signing, verification, packing, sampler, ...).

MODE ?= 128
REF  ?= ./ref/SHUTTLE-$(MODE)
CC   ?= gcc
NTTDIR := $(dir $(wildcard $(REF)/ntt/*/ntt_ref.c))
CFLAGS ?= -O3 -march=native -std=gnu11 -I$(REF) $(addprefix -I,$(NTTDIR)) -DSHUTTLE_MODE=$(MODE)
LDLIBS ?= -lm

# every reference .c (top level + the parameter-specific NTT) except the
# KAT / self-test / prior-analysis drivers
REFSRC := $(filter-out %/KAT_SIG.c %/test.c %/cycles_test.c %/leak_test.c \
                       %/keyrec.c %/fullbreak.c %/fullbreak_nosecret.c %/irs_flipped.c, \
                       $(wildcard $(REF)/*.c)) $(wildcard $(REF)/ntt/*/ntt_ref.c)

all: key_recovery leak_probe

key_recovery: src/key_recovery.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

leak_probe: src/leak_probe.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f key_recovery leak_probe

.PHONY: all clean
