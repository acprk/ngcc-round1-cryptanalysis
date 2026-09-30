# UVW-KEM decapsulation harness (leak / shared-DRNG / malformed-ciphertext tests).
# Point REF at one UVW-KEM reference level directory, e.g.
#   make REF=/path/to/Reference_Implementation/UVW-KEM-256
# The reference implementation is NOT bundled; src/test_uvw.c never modifies it.
CC  ?= gcc-11
REF ?= ../src/UVW_Key_Encapsulation_Mechanism/Implementations/Reference_Implementation/UVW-KEM-128
# reference core only: drop KAT_KEM.c (own main + global drng_algorithm)
REFSRC := $(REF)/src/KEM_AlgorithmInstance.c $(REF)/src/drng.c $(REF)/src/gf_math.c \
          $(REF)/src/auxfunc.c $(REF)/src/list_decoding.c $(REF)/src/uvw_constants.c
OUT ?= test_uvw

all: $(OUT) $(OUT)_asan
$(OUT): src/test_uvw.c $(REFSRC)
	$(CC) -O2 -w -I$(REF)/include $^ -o $@ -lm
$(OUT)_asan: src/test_uvw.c $(REFSRC)
	$(CC) -O1 -g -w -fsanitize=address -I$(REF)/include $^ -o $@ -lm
clean:
	rm -f test_uvw* 
.PHONY: all clean
