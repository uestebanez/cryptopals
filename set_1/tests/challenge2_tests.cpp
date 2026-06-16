#include <cstdlib>
#include <gtest/gtest.h>
#include "fixed_xor.h"

#define FIXED_XOR_INPUT (const char*)"1c0111001f010100061a024b53535009181c"

TEST(fixed_xor, FixedXorEmpty) {
  ASSERT_EQ(-1,fixed_xor(NULL,NULL,NULL));
}

TEST(fixed_xor, FixedXorOddString) {
  char output[3];
  ASSERT_EQ(-2,fixed_xor("A","A",output));
}

TEST(fixed_xor, FixedXorSameByte) {
  char output[3];
  ASSERT_EQ(0,fixed_xor("AA","AA",output));
  EXPECT_STREQ(output,"00");
}

TEST(fixed_xor, FixedXorCompleteString) {
  char output[strlen(FIXED_XOR_INPUT)+1];
  ASSERT_EQ(0,fixed_xor(FIXED_XOR_INPUT ,
            "686974207468652062756c6c277320657965",output));
  EXPECT_STREQ(output,"746865206b696420646f6e277420706c6179");
}

