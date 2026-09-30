Subject: Re: Round1: Public Comment: UVW Key Encapsulation Mechanism - kem-38-2 fix is not sufficient

Dear UVW Team, dear all,

Following Markku-Juhani Saarinen's kem-38-2 on ngcc.dev and Tianyuan Xie's reaction attack in this thread: making decapsulation constant-time does not remove the leak.

1. Overall DFR is about 2^-43, and failures reveal the hidden pairs

Theorem 2 gives only the single-attempt success probability. We use the same counting, conditioning on t = the number of hidden pairs with e1(i) = e2(i) != 0. For one attempt this gives exactly 0.988123 / 0.987827 / 0.987803, as in the spec. After the 1000 attempts in the code (KEM_AlgorithmInstance.c:1256), the overall DFR is:

  UVW-128: 2^-43.3    UVW-256: 2^-42.1    UVW-512: 2^-41.7

More retries help slowly (UVW-128: 10^4 -> 2^-63.0, 10^6 -> 2^-108.3). Reaching 2^-128 needs about 10^7 attempts, and a constant-time decoder would have to run all of them every time.

A ciphertext fails only if t >= 4 (mostly t = 5). Each such pair is a triple e[a] = gamma * e[b] != 0 in public coordinates, as in Tianyuan Xie's attack. The attacker encapsulates honestly and records the ciphertexts whose decapsulation does not return its key. This needs no timing, and it works with a single status code and implicit rejection. In a simulation at the UVW-128 size, 1000 failures recover all 430 pairs and ratios (500 failures: 416/430). That is about 2^53 queries: within the usual 2^64 IND-CCA budget, though not practical. After that, stages 3-4 of Tianyuan Xie's post apply. We did not rerun them, and UVW-256/512 are extrapolated.

The specification should state the overall DFR and include it in the FO bound. Retrying I1 cannot make the DFR negligible; the decoder or the parameters need to change.

2. Minor

- UVW-256/512 allocate GU_I1 and GU_I1_inv in every retry and never free them (:1312/:1313). ASan measures 2 x 364,658 B / 2 x 1,455,218 B leaked per honest decapsulation. A 1-byte-modified ciphertext runs all 1000 retries and leaks about 0.7 GB / 2.9 GB.
- The I1 choices use the global drng_algorithm, so each decapsulation changes the output of the next kem_enc.

Code and logs: https://github.com/acprk/ngcc-round1-cryptanalysis/tree/main/uvw-kem-dfr-reaction

This analysis was prepared with AI assistance.

Best regards,
[NAME]
