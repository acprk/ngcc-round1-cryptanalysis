# Build the PolarLAC key-recovery attack against the reference implementation.
#
#   make REF=/path/to/Reference_Implementation/POLARLAC-Light
#
# REF must point at the PolarLAC-Light reference-implementation source directory.
# The attack links directly against the unmodified scheme sources.
#
# The key-recovery pipeline (attack, finish) uses a plaintext-checking oracle,
# realised in this build by the reference PKE_Decrypt (message-flip check). The
# timing realisation of that oracle is validated separately by oracle_time,
# which needs the two-line rejection-counter instrumentation described in README.

REF ?= ./ref/POLARLAC-Light
CC  ?= gcc
CFLAGS ?= -O3 -march=native -std=gnu11 -I$(REF) -Isrc
LDLIBS ?= -lm

# reference .c except the KAT / self-test drivers
REFSRC := $(filter-out %/KAT_KEM.c %/test.c %/cycles_test.c, $(wildcard $(REF)/*.c))

all: attack finish

attack: src/attack.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

finish: src/finish.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

# timing-oracle validation (needs the instrumented pke.c, see README)
oracle_time: src/oracle_time.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f attack finish oracle_time

.PHONY: all clean
