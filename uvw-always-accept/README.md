# The discarded verdict: universal forgery of UVW_signature

A universal forgery of **UVW_signature** (ICCS NGCC round-1 code-based hash-and-sign,
Wave/GPV lineage over F3). The shipped NGCC verifier computes the correct verification
result and then throws it away, returning "valid" for **every** message/signature pair.
Forgery is: submit any bytes.

## Why it works (one line of code)

`sig_verify` in `SIG_AlgorithmInstance.c` (the official NGCC verifier entry point, where
return value `0` means "valid") is:

```c
int result = uvw_verify(pk_obj, &ctx, sn_obj) ? 0 : -1;  /* correct verdict computed... */
...
return 0;                                                /* ...then discarded: always ACCEPT */
```

`result` is dead. The function returns `0` unconditionally, so the deployed verifier
accepts any input. This is present in **all six submitted files** (Reference and Optimized,
UVW-128/256/512). This is an implementation catastrophe, not a cryptanalysis of the UVW
design; the fix is one line, `return result;`.

## Threat model and purity

EUF-CMA against the shipped verifier. The demo uses only the reference `sig_keygen`,
`sig_sign`, `sig_verify`. It never inspects the secret key beyond the honest signing call.
`src/` is not modified; the harness is built against the reference sources with `-DUSE_API_PKC`
(the SM3 backend the NGCC API mandates, as in the submission's own Makefile).

## Layout

```
src/apitamper.c   sign honestly, then verify (a) the honest sig, (b) a byte-flipped sig,
                  (c) a fully random signature buffer, (d) the honest sig under a wrong
                  message; print each verdict.
Makefile, run_all.sh
```

## Build and run

```
REFROOT="/path/to/Implementations/Reference_Implementation" ./run_all.sh
```

or directly:

```
make REF=/path/to/Reference_Implementation/UVW-128 apitamper
./apitamper
```

The reference implementation is NOT bundled. (If you only have the staged copy, point
`REF` at `build/UVW_signature/ref/UVW-128`, a byte-identical reference tree.)

## Expected output

```
API sig_verify: honest=0 tampered=0 garbage=0 wrongmsg=0 (0=ACCEPT)
```

All four are accepted: a byte-flipped signature, a fully random signature, and a wrong
message all verify as valid.

## Notes

* The verifier is not a no-op: it **runs the full `uvw_verify` check** (~0.2 s per call) and
  computes the correct verdict — it simply discards `result` and returns `0` regardless. So the
  cost of verification is unchanged; only the verdict is thrown away.
* Independently of this implementation break, two design points merit deeper review (not
  demonstrated here): the large-weight ternary DOOM forgery margin is thin (about 5.7
  classical / 0.8 quantum bits over target), and the signature sampler's uniformity over
  the large-weight sphere (assumed by the EUF-CMA proof) is not established for these
  parameters, the classical NTRUSign/SURF leakage vector.
* Fix: `return result;`.
