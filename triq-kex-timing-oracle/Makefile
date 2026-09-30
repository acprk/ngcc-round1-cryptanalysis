# TriQ-KEX / TriQ-KEM timing-oracle verification harnesses.
# Point REF at a TriQ-KEX reference-implementation level directory, e.g.
#   make REF=/path/to/Reference_Implementation/TriQ-KEX-128
# The reference implementation is NOT bundled; src/ (our harnesses) never modifies it.
CC  ?= gcc-11
REF ?= ../src/TriQ-KEX/Implementations/Reference_Implementation/TriQ-KEX-128

INC := -I$(REF) -I$(REF)/src/common -I$(REF)/src/common/triq-128 -I$(REF)/src/ref -I$(REF)/src/ref/triq-128
# reference crypto core only: drop the KAT driver and API wrapper (own main / global DRNG needs)
REFSRC := $(REF)/src/common/code.c $(REF)/src/common/crypto_memset.c $(REF)/src/common/fft.c \
          $(REF)/src/common/kem.c $(REF)/src/common/symmetric.c \
          $(REF)/src/ref/gf.c $(REF)/src/ref/gf2x.c $(REF)/src/ref/triq_pke.c $(REF)/src/ref/parsing.c \
          $(REF)/src/ref/reed_muller.c $(REF)/src/ref/reed_solomon.c $(REF)/src/ref/vector.c \
          $(REF)/drng.c $(REF)/auxfunc.c

all: micro harness_bdtime exp_oracle

micro: src/micro.c $(REFSRC)
	$(CC) -std=c99 -O3 -w $(INC) $^ -o $@ -lm
harness_bdtime: src/harness_bdtime.c $(REFSRC)
	$(CC) -std=c99 -O3 -w $(INC) $^ -o $@ -lm
exp_oracle: src/exp_oracle.c $(REFSRC)
	$(CC) -std=c99 -O3 -w $(INC) $^ -o $@ -lm

clean:
	rm -f micro harness_bdtime exp_oracle
.PHONY: all clean
