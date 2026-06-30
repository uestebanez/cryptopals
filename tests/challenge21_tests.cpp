#include <cstdlib>
#include <gtest/gtest.h>
#include "mt19937.h"

TEST(mt19937, wrong_params) {
  mt19937_seed(NULL,5489);
  ASSERT_EQ(0,mt19937_extract(NULL));
}

TEST(mt19937, fixed_seed) {
  mt19937_t rng;
  mt19937_seed(&rng,5489);
  ASSERT_EQ(3499211612,mt19937_extract(&rng));
}


