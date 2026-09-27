# Build the Aigis-Enc+ decryption-oracle attack against the reference impl.
#
#   make PARAMS=1 REF=/path/to/Reference_Implementation/Aigis-Enc+-I
#   make PARAMS=2 REF=/path/to/Reference_Implementation/Aigis-Enc+-II
#   make PARAMS=3 REF=/path/to/Reference_Implementation/Aigis-Enc+-III
#
# REF must point at an Aigis-Enc+ reference-implementation source directory for
# the matching parameter set (I=1 / II=2 / III=3). The attack links directly
# against the UNMODIFIED scheme sources (kem.c, owcpa.c, poly*, ntt, pack,
# hashkdf, fips202, ...). We do NOT ship the reference implementation.
#
# We build with -DUSE_SHA3 (the config of the shipped `speed*` targets): the FO
# defect is hash-independent, and USE_SHA3 keeps the package self-contained
# (no Intel-IPP SM3 / NGCC-DRNG externals). fips202x4.c (AVX keccak4x, Windows
# include path) and sm3kdf.c (needs ippcp) are excluded; neither is used here.

PARAMS ?= 1
REF    ?= ./ref/Aigis-Enc+-I
CC     ?= gcc
CFLAGS ?= -O2 -march=native -std=c99 -Wno-incompatible-pointer-types \
          -DPARAMS=$(PARAMS) -DUSE_SHA3 -I$(REF)
LDLIBS ?= -lm

# every reference .c except AVX keccak, the SM3-IPP shim, and any KAT driver
REFSRC := $(filter-out %/fips202x4.c %/sm3kdf.c %/KAT_KEM.c, $(wildcard $(REF)/*.c))

all: oracle recover

oracle: src/oracle.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

recover: src/recover.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -f oracle recover

.PHONY: all clean
