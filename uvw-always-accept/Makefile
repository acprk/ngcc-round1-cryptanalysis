# UVW_signature always-accept verifier: universal forgery demonstration.
# Point REF at a UVW reference-implementation level directory, e.g.
#   make REF=/path/to/Reference_Implementation/UVW-128
# The reference implementation is NOT bundled; src/ is never modified.
# -DUSE_API_PKC selects the SM3 hash/PRNG backend the NGCC API mandates (as in the
# submission's own Makefile), which also avoids the optional keccak headers.
CC  ?= gcc-11
REF ?= ../src/UVW_signature/Implementations/Reference_Implementation/UVW-128
# reference crypto sources (top-level minus the KAT driver's main, plus fq_arithmetic)
REFSRC := $(filter-out %KAT_SIG.c,$(wildcard $(REF)/*.c)) $(wildcard $(REF)/fq_arithmetic/*.c)

apitamper: src/apitamper.c $(REFSRC)
	$(CC) -DUSE_API_PKC -O2 -I$(REF) $^ -o $@

clean:
	rm -f apitamper
.PHONY: clean
