#include <cstdlib>
#include <gtest/gtest.h>
#include "base64.h"

TEST(Base64, Str2Bytes) {
  const char *hex_string = "AABB";
  uint8_t *buffer = str2bytes(hex_string);

  ASSERT_NE(buffer, nullptr);
  EXPECT_EQ(buffer[0], 0xAA);
  EXPECT_EQ(buffer[1], 0xBB);

  free(buffer);
}
