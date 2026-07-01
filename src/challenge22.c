#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include "mt19937.h"
#include "random.h"

static uint32_t oracle(uint32_t *fake_time, uint32_t *real_seed)
{
  size_t wait;
  uint32_t seed;
  mt19937_t rng;

  // simulate the wait
  random_range(40, 1000, &wait);
  *fake_time += wait;
  seed = *fake_time;
  
  if( real_seed != NULL ) {
    *real_seed = seed;
  }
  mt19937_seed(&rng,seed);
  random_range(40,1000,&wait);
  *fake_time += wait;
  return mt19937_extract(&rng);
}


int main(int argc, char** argv)
{
  uint32_t now = 1000000;
  uint32_t real_seed = 0;
 
  srand((unsigned int)time(NULL));
  uint32_t observed = oracle(&now, &real_seed); 
  // this function "takes time" and now is updated
  // real seed is just to check our attack
  printf("observed  = %u\n", observed);
  printf("now       = %u\n", now);
  printf("real seed = %u\n", real_seed);
  
  mt19937_t rng;
  for( uint32_t i = now; i >= now - 1000; i-- ) {

    mt19937_seed(&rng,i);
    uint32_t number = mt19937_extract(&rng);
    if( number == observed ) {
      printf("find seed = %u\n",i);
      break;
    }
  }
  return 0;
}
