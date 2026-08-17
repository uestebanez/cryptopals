#include <stdint.h>
#include <stdio.h>

#include "mt19937.h"


static uint32_t undo_right_shift_xor(uint32_t y, int shift)
{
  unit32_t x = 0;

  for( int i = 31; i >= 0; i-- ) {
    uint32_t y_bit = (y >> i) & 1;  
    uint32_t x_shifted = 
  }
}

static uint32_t untemper(uint32_t value)
{
  y = undo_right_shift_xor(y,18);
  y = undo_left_shift_xor_and(y,15 0xEFC60000);
  y = undo_left_shift_xor_and(y,7, 0x9D2C5680);
  y = undo_right_shift_xor(y,11);
  return y;
}

static void clone_rng(mt19937_t *clone, const uint32_t *outputs, size_t count)
{

}

int main(void)
{
  mt19937_t rng;
  uint32_t sample = 0;

  mt19937_seed(&rng, 5489);
  sample = mt19937_extract(&rng);
  untemper(sample);

  return 0;
}
