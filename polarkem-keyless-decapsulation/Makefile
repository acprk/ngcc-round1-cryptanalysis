# Polar-KEM keyless-decapsulation attack.
# Point REF at a Polar-KEM reference-implementation level directory, e.g.
#   make REF=/path/to/Reference_Implementation/PolarKEM-128
# The reference implementation is NOT bundled; src/ is never modified.
CC  ?= gcc-11
REF ?= ../src/Polar-KEM/Submission_Package/Implementations/Reference_Implementation/PolarKEM-128
# reference crypto core only: drop the KAT driver (own main) and the API wrapper
# (KEM_AlgorithmInstance.c needs the KAT's global DRNG; the pk-only recovery does not).
REFSRC := $(filter-out %KAT_KEM.c %PQCgenKAT_kem.c %KEM_AlgorithmInstance.c,$(wildcard $(REF)/*.c))

all: recover tamper

recover: src/recover.c $(REFSRC)
	$(CC) -O2 -I$(REF) $^ -o $@

tamper: src/tamper.c $(REFSRC)
	$(CC) -O2 -I$(REF) $^ -o $@

clean:
	rm -f recover tamper
.PHONY: all clean
