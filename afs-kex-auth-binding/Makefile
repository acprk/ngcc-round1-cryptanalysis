# AFS-KEX (pMAKE-BW) protocol-layer verification.
# Point REF at ONE reference-implementation level directory, e.g.
#   make REF=/path/to/Reference_Implementation/AFS_KEX_C128
# The reference implementation is NOT bundled; nothing under REF is modified.
CC  ?= gcc-11
REF ?=
ifeq ($(REF),)
$(error set REF=/path/to/Reference_Implementation/AFS_KEX_C128 (or C256/C512))
endif
BASE := $(notdir $(REF))
# per-level compile flags (mirror each level's own Makefile) and a printable label
ifneq (,$(findstring C128,$(BASE)))
  LVLFLAGS := -DBWKEM128_INTERNAL_COMPAT -DBWKEM_C128_USE_ICCS_AUXFUNC -DAFSLEVEL=\"AFS-KEX-C128\"
else ifneq (,$(findstring C256,$(BASE)))
  LVLFLAGS := -DBWKEM_C256_USE_ICCS_AUXFUNC -DAFSLEVEL=\"AFS-KEX-C256\"
else ifneq (,$(findstring C512,$(BASE)))
  LVLFLAGS := -DBWKEM_C512_USE_ICCS_AUXFUNC -DAFSLEVEL=\"AFS-KEX-C512\"
else
  $(error REF dir name must contain C128, C256 or C512)
endif
# reference crypto core: drop the KAT driver and the API wrapper (both bring their own main/state)
REFSRC := $(filter-out %KAT_KEX.c %KEX_AlgorithmInstance.c,$(wildcard $(REF)/*.c))
CFLAGS ?= -O2 -std=c99 -I$(REF) $(LVLFLAGS) -Isrc
BINS := replay_impersonate reply3_refute uks_keycopy failure_oracle negatives
all: $(BINS)
$(BINS): %: src/%.c $(REFSRC)
	$(CC) $(CFLAGS) $^ -o $@
clean:
	rm -f $(BINS)
.PHONY: all clean
