#!/usr/bin/env python3
# ==========================================================================
# BiT key recovery: bias-kernel deconvolution.  AUDIT-CLEAN.
#
# Produces s0_rec.bin (recovered victim secret s0) from PUBLIC inputs only:
#   acc2_victim.bin : bilinear estimator over the VICTIM's honest signatures
#                     (est2.c; reads only public transcripts z0,z_tail,c)
#   acc2_cal.bin    : same estimator over the ATTACKER'S OWN calibration key's
#                     signatures  (public transcripts of a key the attacker made)
#   calkey.bin      : the ATTACKER'S OWN calibration secret s0_cal.  This is NOT
#                     the victim key; the attacker generated this keypair itself,
#                     so its secret is legitimately known.  Used ONLY to fit the
#                     secret-INDEPENDENT bias kernel H.
#
# The VICTIM secret (key.bin) is read ONLY inside the [SCORING] block below,
# purely to print an exact-coefficient count.  Every victim-sk read is tagged
#   SK-READ [SCORING]
# so an auditor can:   grep -n 'SK-READ' deconv.py   and see all are scoring-only,
# and:                 grep -n 'key.bin' deconv.py    (only appears in SCORING).
# ==========================================================================
import numpy as np
L, N = 3, 256

acc_victim = np.fromfile('acc2_victim.bin', dtype=np.float64).reshape(L, N)  # PUBLIC
acc_cal    = np.fromfile('acc2_cal.bin',    dtype=np.float64).reshape(L, N)  # PUBLIC
s0_cal     = np.fromfile('calkey.bin',      dtype=np.int16)[:L*N].reshape(L, N).astype(float)  # ATTACKER-OWNED cal key

# negacyclic FFT (ring Z[x]/(x^N+1)) via twiddle w_k = exp(-i*pi*k/N)
w = np.exp(-1j*np.pi/N*np.arange(N))
nfft  = lambda a: np.fft.fft(a*w)
nifft = lambda A: (np.fft.ifft(A)/w).real

# Fit the shared, secret-independent bias kernel H from CALIBRATION ONLY:
#   acc_cal[i] ~ H (neg-conv) s0_cal[i]  =>  per-frequency LS ratio.
num = np.zeros(N, complex); den = np.zeros(N, complex)
for i in range(L):
    S = nfft(s0_cal[i]); Ac = nfft(acc_cal[i])
    num += Ac*np.conj(S); den += S*np.conj(S)
H = num/den

# Deconvolve the VICTIM statistic with the calibration kernel, round to ternary.
rec = np.zeros((L, N))
for i in range(L):
    rec[i] = nifft(nfft(acc_victim[i]) / H)
s0_rec = np.clip(np.round(rec), -1, 1).astype(np.int16)

# Baseline WITHOUT deconvolution (public): divide by the kernel's central tap h0 only.
h0 = nifft(H)[0]
s0_direct = np.clip(np.round(acc_victim / h0), -1, 1).astype(np.int16)
s0_rec.tofile('s0_rec.bin')
print("wrote s0_rec.bin  (decoded counts %s)" % {v:int((s0_rec==v).sum()) for v in (-1,0,1)})

# -------------------- [SCORING] (uses VICTIM sk; not part of the attack) -------
try:
    s0_true = np.fromfile('key.bin', dtype=np.int16)[:L*N].reshape(L, N)  # SK-READ [SCORING]
    ex = int((s0_rec.flatten() == s0_true.flatten()).sum())
    print("[SCORING] s0_rec exact %d/768" % ex)
    exd = int((s0_direct.flatten() == s0_true.flatten()).sum())
    print("[SCORING] direct estimator (acc/h0, no deconvolution) exact %d/768" % exd)
except FileNotFoundError:
    print("[SCORING] key.bin absent; skipping score")

# -------------------- CONTROL (optional, public-only) --------------------------
# If acc2_ctrl.bin exists (estimator with an INDEPENDENT random sign, i.e. NO
# shared bimodal bit), deconvolve it with the SAME H and show recovery collapses.
import os
if os.path.exists('acc2_ctrl.bin'):
    acc_ctrl = np.fromfile('acc2_ctrl.bin', dtype=np.float64).reshape(L, N)  # PUBLIC
    rc = np.zeros((L, N))
    for i in range(L):
        rc[i] = nifft(nfft(acc_ctrl[i]) / H)
    s0_ctrl = np.clip(np.round(rc), -1, 1).astype(np.int16)
    try:
        s0_true = np.fromfile('key.bin', dtype=np.int16)[:L*N].reshape(L, N)  # SK-READ [SCORING]
        exc = int((s0_ctrl.flatten() == s0_true.flatten()).sum())
        corr = np.corrcoef(rc.flatten(), s0_true.flatten().astype(float))[0,1]
        print("[SCORING/CONTROL] no-shared-sign estimator: exact %d/768  corr=%.4f (expect ~chance / ~0)" % (exc, corr))
    except FileNotFoundError:
        print("[CONTROL] key.bin absent; skipping control score")
