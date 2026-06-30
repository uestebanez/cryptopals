#include "mt19937.h"

#define MT_N 624
#define MT_M 397
#define MT_W 32
#define MT_R 31

#define MT_A 0x9908B0DF
#define MT_U 11
#define MT_D 0xFFFFFFFF
#define MT_S 7
#define MT_B 0x9D2C5680
#define MT_T 15
#define MT_C 0xEFC60000
#define MT_L 18
#define MT_F 1812433253

#define LOWER_MASK 0x7FFFFFFF
#define UPPER_MASK 0x80000000

static void mt19937_twist(mt19937_t *rng)
{
  for (size_t i = 0; i < MT_N; i++) {
      uint32_t x = (rng->mt[i] & UPPER_MASK) |
                   (rng->mt[(i + 1) % MT_N] & LOWER_MASK);

      uint32_t xA = x >> 1;

      if (x & 1) {
          xA ^= MT_A;
      }

      rng->mt[i] = rng->mt[(i + MT_M) % MT_N] ^ xA;
  }

  rng->index = 0;
}

void mt19937_seed(mt19937_t *rng, uint32_t seed)
{
  if( NULL == rng )
    return;

  rng->index = MT_N;
  rng->mt[0] = seed;

  for (size_t i = 1; i < MT_N; i++) {
      rng->mt[i] = MT_F * (rng->mt[i - 1] ^ (rng->mt[i - 1] >> 30)) + i;
  }
}

uint32_t mt19937_extract(mt19937_t *rng)
{
  if ( NULL == rng )
    return 0;

  if (rng->index >= MT_N) {
      mt19937_twist(rng);
  }

  uint32_t y = rng->mt[rng->index++];

  y ^= (y >> MT_U) & MT_D;
  y ^= (y << MT_S) & MT_B;
  y ^= (y << MT_T) & MT_C;
  y ^= (y >> MT_L);

  return y;
}


