Round1: Public Comment: TriQ-KEX  (also applies to TriQ-KEM)

Subject: Static-key decapsulation is not constant-time — same class of timing PCO that broke HQC

This is the same class of vulnerability that broke HQC. TriQ is HQC-family, and its FO
re-encryption regenerates the encryption randomness r1, r2 from the decrypted message with
`vect_sample_fixed_weight_bd`, a rejection loop with an early `break` (src/ref/vector.c:249-254,
called from triq_pke_encrypt at src/ref/triq_pke.c:96,98) whose iteration count depends on the
decrypted message. So decapsulation time is a plaintext-checking oracle on the secret key. This
is exactly the "Don't reject this" hazard (Guo, Hlauschek, Johansson, Lahr, Nilsson, Schröder,
TCHES 2022, ePrint 2021/1485), which HQC removed by adopting a rejection-free sampler; TriQ's
bounded-density rule re-introduces it. The leak happens before the constant-time implicit-rejection
compare (kem.c:169-174), so FO masking does not hide it. In TriQ-KEX (FSXY AKE) any network party
can submit chosen CT_A to the responder or CT_B to the initiator, so the oracle is available on
both long-term keys.

Measured (reference TriQ-KEX-128, gcc-11 -O3; the timing harness must be pinned to an isolated
idle core, otherwise the channel is swamped by scheduler/frequency-scaling jitter):

  - one extra bounded-density iteration = ~15.7k ticks (support_gen 11.5k + bd_check 4.2k)
  - min-of-31 full decapsulation, by resample class:
      class0 (0)  n=3683  mean 10,220,477 ticks
      class1 (1)  n=293   mean 10,257,704 ticks   delta +37,227 ticks, z ~ 4.4 sigma
      class2+     n=24    mean 10,394,078 ticks   (+173,601; mean monotone in resample count)
  - rejection frequency ~7.9% of messages; a quieter host gave delta +31,725 at 5.6 sigma and
    49% TPR @ 1% FPR single-shot, sufficient to instantiate the PCO.

Full key recovery is a GJS/PCO distance-spectrum recovery of the same type as 2021/1485 (HQC-128
there needed ~8.7e5 idealized queries); it is a compute-heavy follow-up in progress. The
structural groundwork is done and verified against the reference decoder: RS(42,16) corrects 13
symbol errors, each symbol is a 384-bit block = 3 copies of RM(1,7) voted, per-block flip radius
~33 aligned errors (99 raw flips), giving a sharp decode-success boundary at 13->14 corrupted
message-region blocks. Recovery numbers will be updated in the package.

Fix: a constant-iteration bounded-density sampler (fixed candidate count with masked selection),
applied to TriQ-KEM and TriQ-KEX alike.

Reproduction harnesses, measurements, and key-recovery groundwork:
https://github.com/acprk/ngcc-round1-cryptanalysis/tree/main/triq-kex-timing-oracle
