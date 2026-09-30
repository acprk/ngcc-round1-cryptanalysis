#include <stdio.h>
#include "drng.h"
#include "SIG_AlgorithmInstance.h"
#include "internal.h"
DRNG_ctx drng_algorithm;
int main(void){ const sydo_ref_paramset_t* P=sydo_ref_get_paramset_by_name(ALGORITHM_INSTANCE);
 sydo_ref_signature_layout_t L=sydo_ref_signature_layout(P);
 printf("%s lambda=%u tau=%u zero_bits_param=%u delta_bits=%zu enforced_zero_bits=%zu delta_off=%zu delta_size=%zu iv_off=%zu iv_size=%zu grind_off=%zu total=%zu\n",
  P->name,P->secpar_bits,P->tau,P->zero_bits_in_delta,sydo_ref_delta_bits(P),sydo_ref_unused_delta_bits(P),
  L.delta_offset,L.delta_size,L.iv_offset,L.iv_size,L.grinding_counter_offset,L.total_size); return 0;}
