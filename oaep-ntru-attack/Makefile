# Build the Coset-Lift Malleability attack (and the Rejection Key-Leak probe)
# against the OAEP-NTRU reference implementation.
#
#   make REF=/path/to/Reference_Implementation/OAEP-NTRU-648
#   make REF=/path/to/Reference_Implementation/OAEP-NTRU-1296
#   make REF=/path/to/Reference_Implementation/OAEP-NTRU-2592
#
# REF must point at ONE OAEP-NTRU reference-implementation source directory (a
# single parameter set). The attack links directly against the unmodified
# scheme sources (poly, ntt, drng, symmetric, KEM_AlgorithmInstance). The
# reference implementation is NOT bundled with this package.

REF ?= ./ref/OAEP-NTRU-648
CC  ?= gcc
CFLAGS ?= -O3 -fomit-frame-pointer -funroll-loops -Wno-unused-result -std=gnu11 -I$(REF)
LDLIBS ?= -lm

# every reference .c EXCEPT the KAT driver (it defines main and the drng global,
# both of which our attack drivers provide themselves).
REFSRC := $(filter-out %/KAT_KEM.c, $(wildcard $(REF)/*.c))

all: coset_lift reject_leak

coset_lift: src/coset_lift.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

reject_leak: src/reject_leak.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f coset_lift reject_leak

.PHONY: all clean
