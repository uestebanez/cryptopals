#include <cstdlib>
#include <gtest/gtest.h>
#include "repeating_xor.h"
#include "convert.h"

#define INPUT (const char*)"Burning 'em, if you ain't quick and nimble\n" \
                           "I go crazy when I hear a cymbal"

TEST(repeating_xor, RepeatingXorEmpty) {
  ASSERT_EQ(-1,repeating_xor(NULL,NULL,NULL));
}

TEST(repeating_xor, RepeatingXorOddString) {
  char output[3];
  ASSERT_EQ(-2,repeating_xor("A","A",output));
}

TEST(repeating_xor, RepeatingXorSameByte) {
  char output[3];
  ASSERT_EQ(0,repeating_xor("AA","AA",output));
  EXPECT_STREQ(output,"00");
}

TEST(repeating_xor, RepeatingXorPartString) {
  char clear[7]; // 3*2 + 1
  char output[7];
  char key[7];
 
  ascii2hex_ascii("Bur",clear);
  ascii2hex_ascii("ICE",key);
  ASSERT_EQ(0,repeating_xor(clear,key,output));
  EXPECT_STREQ(output,"0b3637");
}

TEST(repeating_xor, RepeatingXorCompleteString) {
  char clear[(strlen(INPUT)*2)+1]; 
  char output[sizeof(clear)];
  char key[(strlen("ICE")*2)+1];
 
  ascii2hex_ascii(INPUT,clear);
  ascii2hex_ascii("ICE",key);
  printf("key:[%s]\n",key);
  printf("clear:[%s]\n",clear);
  ASSERT_EQ(0,repeating_xor(clear,key,output));
  printf("output:[%s]\n",output);
  EXPECT_STREQ(output,"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
}
