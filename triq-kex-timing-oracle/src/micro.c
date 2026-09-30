#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "parameters.h"
#include "symmetric.h"
#include "vector.h"
static inline uint64_t rdtsc(void){ unsigned lo,hi; __asm__ volatile("lfence\nrdtsc":"=a"(lo),"=d"(hi)); return ((uint64_t)hi<<32)|lo; }
int main(){ uint8_t th[SEED_BYTES]={7}; triq_xof_ctx c; uint32_t s[PARAM_OMEGA_MAX]; uint64_t best=~0ull, best2=~0ull; volatile uint8_t sink=0;
 for(int r=0;r<2000;r++){ xof_init(&c,th,SEED_BYTES); uint64_t t0=rdtsc(); vect_generate_random_support2(&c,s,PARAM_OMEGA_R); uint64_t t1=rdtsc(); sink^=vect_check_bounded_density(s,PARAM_OMEGA_R,PARAM_BD_L,PARAM_BD_GAMMA); uint64_t t2=rdtsc(); if(t1-t0<best)best=t1-t0; if(t2-t1<best2)best2=t2-t1; }
 printf("one resample iteration: support_gen=%lu cycles, bd_check=%lu cycles, total=%lu\n",(unsigned long)best,(unsigned long)best2,(unsigned long)(best+best2)); return 0; }
