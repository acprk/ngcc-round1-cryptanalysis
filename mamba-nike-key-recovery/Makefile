# MAMBA-NIKE static-key recovery (key-mismatch / reaction attack).
# Point REF at a reference-implementation level directory, e.g.
#   make REF=/path/to/Reference_Implementation/MAMBA-NIKE-128 attack
#   make REF=/path/to/Reference_Implementation/MAMBA-NIKE-384 attackgen
# The reference implementation is NOT bundled; src/ is never modified. The reference's
# own -DSTATISTICAL_TEST build exposes rec() as the reconciliation (reaction) oracle.
CC     ?= gcc-11
REF    ?= ../src/MAMBA-NIKE/Implementations/Reference_Implementation/MAMBA-NIKE-128
CFLAGS  = -std=c99 -O3 -I$(REF) -D_POSIX_C_SOURCE=199309L
SUPPORT = crypto_stream_chacha20 poly toom error_correction reduce fips202
SUPP_O  = $(addsuffix .o,$(SUPPORT))

%.o: $(REF)/%.c
	$(CC) $(CFLAGS) -c $< -o $@
nike_stat.o: $(REF)/nike.c
	$(CC) $(CFLAGS) -DSTATISTICAL_TEST -c $< -o $@
harness.o: src/harness.c
	$(CC) $(CFLAGS) -c $< -o $@

attack: src/attack.c harness.o nike_stat.o $(SUPP_O)      # MAMBA-NIKE-128 end-to-end
	$(CC) $(CFLAGS) -o $@ $^ -lm
attackgen: src/attack_gen.c harness.o nike_stat.o $(SUPP_O) # generic driver (eta<=3 profiles)
	$(CC) $(CFLAGS) -o $@ $^ -lm

clean:
	rm -f attack attackgen *.o
.PHONY: clean
