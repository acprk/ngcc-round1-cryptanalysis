# What does SYDO's own Theorem 25 give, before any grinding is counted?
#
# Theorem 25's soundness term is  (Q_{2,1} + Q_{2,2} + Q_{2,3} + 9) * (d-1) / 2^lambda,
# which carries NO grinding term. Read as "work to succeed with constant probability",
# that is 2^lambda / (d-1), i.e. lambda - log2(d-1) bits.
#
# The EUF-KO reduction is Katz-Wang, so it also pays the loss factor 1/(1 - rho_RSD),
# where the spec (Sec 6, just after Theorem 25) defines the RSD density as
#
#       rho_RSD = (n/w)^w / 2^(n-k)
#
# Everything below comes from the spec's own Tables 5.2/5.3; nothing is measured.
from math import log2

# (n, n-k, w) per level, spec Table 5.2; d = 4 is the constraint degree (Table 5.3).
PARAMS = {160: (16461, 480, 59), 256: (26226, 768, 94), 512: (49941, 1456, 179)}
d = 4

print(f'{"level":>6} {"n/w":>5} {"log2 rho_RSD":>13} {"KW loss (bits)":>15} {"Thm25 bound":>12} {"claimed":>8}')
for lam, (n, nk, w) in PARAMS.items():
    m = n // w
    log2_rho = w * log2(m) - nk
    rho = 2.0 ** log2_rho
    loss_bits = log2(1.0 / (1.0 - rho))
    bound = lam - log2(d - 1) - loss_bits
    print(f'{lam:>6} {m:>5} {log2_rho:>+13.3f} {loss_bits:>15.3f} {bound:>12.2f} {lam:>8}')

print()
print('So the author\'s own theorem yields roughly 157.0 / 254.3 / 509.9, not lambda.')
print('The claimed "exactly lambda" comes only from the Table 5.3 equality')
print('tau*log2(N) - log2(d) + wgrind = lambda, which (see F1) cannot be instantiated.')
