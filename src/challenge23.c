#include <stdint.h>
#include <stdio.h>

#include "mt19937.h"


static uint32_t undo_right_shift_xor(uint32_t y, int shift)
{
  uint32_t x = y;

  for (int i = shift; i < 32; i += shift)
    x = y ^ (x >> shift);

  return x;
}

static uint32_t undo_left_shift_xor_and(uint32_t y, int shift,
                                        uint32_t mask)
{
  uint32_t x = y;

  for (int i = shift; i < 32; i += shift)
    x = y ^ ((x << shift) & mask);

  return x;
}

static uint32_t untemper(uint32_t value)
{
  uint32_t y = value;

  y = undo_right_shift_xor(y,18);
  y = undo_left_shift_xor_and(y,15, 0xEFC60000);
  y = undo_left_shift_xor_and(y,7, 0x9D2C5680);
  y = undo_right_shift_xor(y,11);
  return y;
}

static void clone_rng(mt19937_t *clone, mt19937_t *rng)
{
  if (clone == NULL || rng == NULL)
    return;

  for (size_t i = 0; i < sizeof(clone->mt) / sizeof(clone->mt[0]); i++) {
    uint32_t output = mt19937_extract(rng);

    clone->mt[i] = untemper(output);
  }

  /* Las 624 salidas reconstruyen el estado que seguirá al próximo twist. */
  clone->index = sizeof(clone->mt) / sizeof(clone->mt[0]);
}

int main(void)
{
  mt19937_t rng;
  mt19937_t clone;

  mt19937_seed(&rng, 5489);
  clone_rng(&clone, &rng);

  uint32_t original_output = mt19937_extract(&rng);
  uint32_t clone_output = mt19937_extract(&clone);

  printf("Salida original: %u\n", original_output);
  printf("Salida clonada:  %u\n", clone_output);

  if (original_output != clone_output) {
    printf("Las salidas no coinciden.\n");
    return 1;
  }

  printf("Las salidas coinciden.\n");
  return 0;
}
