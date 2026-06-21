#include <cstdlib>
#include <gtest/gtest.h>
#include "hamming.h"


TEST(hamming, test2sentences) {
  const char* a = "this is a test";
  const char* b = "wokka wokka!!!";

  ASSERT_EQ(37,hamming_distance((const uint8_t*)a,(const uint8_t*)b,strlen(a)));
}
