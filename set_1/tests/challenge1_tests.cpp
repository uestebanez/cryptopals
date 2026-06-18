#include <cstdlib>
#include <math.h>
#include <gtest/gtest.h>
#include "base64.h"
#include "convert.h"

TEST(Base64, Str2BytesBasicConversion) {
  const char *hex_string = "AABB";
  uint8_t *buffer;

  ASSERT_EQ(2,str2bytes(hex_string,&buffer));
  ASSERT_NE(buffer, nullptr);
  EXPECT_EQ(buffer[0], 0xAA);
  EXPECT_EQ(buffer[1], 0xBB);

  free(buffer);
}

TEST(Base64, Str2BytesEmptyString) {
  const char *hex_string = "";
  uint8_t *buffer;
  ASSERT_EQ(0,str2bytes(hex_string,&buffer));
}

TEST(Base64, Str2BytesOddString) {
  const char *hex_string = "A";
  uint8_t *buffer;

  ASSERT_EQ(0,str2bytes(hex_string,&buffer));
  hex_string = "AAA";
  ASSERT_EQ(0,str2bytes(hex_string,&buffer));
}

TEST(Base64, str2base64EmptyBuffer) {
  ASSERT_EQ(-1,str2base64(NULL,NULL));
}

TEST(Base64, base642strEmptyBuffer) {
  ASSERT_EQ(-1,base642str(NULL,NULL));
}
  
TEST(Base64, str2base64LittleBuffer) {
  char buffer[3];
  ASSERT_EQ(-1,str2base64("/w=",NULL));
  ASSERT_EQ(-2,str2base64("/w=",buffer));
}

TEST(Base64, base642strOddBuffer) {
  char buffer[3];
  ASSERT_EQ(-1,base642str("A",NULL));
  ASSERT_EQ(-2,base642str("A",buffer));
}

TEST(Base64, str2base641Byte) {
  char base64[5]={0};
  const char* expected = "AA==";
  ASSERT_EQ(0,str2base64("00",base64));
  ASSERT_EQ(0,strcmp(base64,expected));
  expected = "EA==";
  ASSERT_EQ(0,str2base64("10",base64));
  ASSERT_EQ(0,strcmp(base64,expected));

}

TEST(Base64, base642str1Byte) {
  char str[5]={0};
  ASSERT_EQ(0,base642str("AA==",str));
  EXPECT_STREQ(str,"00");
  ASSERT_EQ(0,base642str("EA==",str));
  EXPECT_STREQ(str,"10");
}

TEST(Base64, str2base642Bytes) {
  char base64[5] = {0};
  const char* expected = "AAE=";
  ASSERT_EQ(0,str2base64("0001",base64));
  ASSERT_EQ(0,strcmp(base64,expected));
  expected = "//8=";
  ASSERT_EQ(0,str2base64("FFFF",base64));
  ASSERT_EQ(0,strcmp(base64,expected));

}

TEST(Base64, base642str2Byte) {
  char str[5]={0};
  ASSERT_EQ(0,base642str("AAE=",str));
  EXPECT_STREQ(str,"0001");
  ASSERT_EQ(0,base642str("//8=",str));
  EXPECT_STREQ(str,"FFFF");
}

TEST(Base64, str2base643Bytes) {
  char base64[5] = {0};
  const char* expected = "AAAA";
  ASSERT_EQ(0,str2base64("000000",base64));
  ASSERT_EQ(0,strcmp(base64,expected));
  expected = "SGVs";
  ASSERT_EQ(0,str2base64("48656C",base64));
  ASSERT_EQ(0,strcmp(base64,expected));
}

TEST(Base64, base642str3Byte) {
  char str[7]={0};
  ASSERT_EQ(0,base642str("AAAA",str));
  EXPECT_STREQ(str,"000000");
  ASSERT_EQ(0,base642str("SGVs",str));
  EXPECT_STREQ(str,"48656C");
}

TEST(Base64, str2base64challenge1) {
  const char* str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  const char* expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  char base64[4*(unsigned)ceil(strlen(str)/3.0)] = {0};
  ASSERT_EQ(0,str2base64(str,base64));
  ASSERT_EQ(0,strcmp(base64,expected));
}

TEST(Base64, base642strLong) {
  char str[128]={0};
  ASSERT_EQ(0,base642str("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",str));
  EXPECT_STREQ(str,"49276D206B696C6C696E6720796F757220627261696E206C696B65206120706F69736F6E6F7573206D757368726F6F6D");
}
