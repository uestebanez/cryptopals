#include <cstdlib>
#include <gtest/gtest.h>
#include "pkcs7.h"


TEST(pkcs7, wrong_input) {
  uint8_t buf[] = {0x00,0x10};
  ASSERT_EQ(-1,pkcs7_pad(NULL,0,0,0));
  ASSERT_EQ(0, pkcs7_pad(buf,0,0,0));
  ASSERT_EQ(-1, pkcs7_pad(buf,sizeof(buf),2,4));
}

TEST(pkcs7, blk_20 ) {
  uint8_t buf[32] = {'Y','E','L','L','O','W',' ','S','U','B','M','A','R','I','N','E'};
  uint8_t expected[20] = {'Y','E','L','L','O','W',' ','S','U','B','M','A','R','I','N','E',0x04,0x04,0x04,0x04};
  ASSERT_EQ(4,pkcs7_pad(buf,sizeof(buf),16,20));
  EXPECT_TRUE(memcmp(expected,buf,20) == 0);
  
  uint8_t expected2[32] = {'Y','E','L','L','O','W',' ','S','U','B','M','A','R','I','N',
    'E',
    0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,
    0x10
  };
 
  ASSERT_EQ(16,pkcs7_pad(buf,sizeof(buf),16,16));
  EXPECT_TRUE(memcmp(expected2,buf,sizeof(buf)) == 0);
}

TEST(pkcs7, blk_4 ) {
  uint8_t buf[4] = {'A'};
  uint8_t expected[4] = {'A',0x03,0x03,0x03};
  ASSERT_EQ(3,pkcs7_pad(buf,sizeof(buf),1,4));
  EXPECT_TRUE(memcmp(expected,buf,sizeof(buf)) == 0);

  uint8_t buf2[4] = {'A','B','C'};
  uint8_t expected2[4] = {'A','B','C',0x01};
  ASSERT_EQ(1,pkcs7_pad(buf2,sizeof(buf2),3,4));
  EXPECT_TRUE(memcmp(expected2,buf2,sizeof(buf2)) == 0);

}

TEST(pkcs7, check_valid_pad) {
  uint8_t buf[] = "ICE ICE BABY\x04\x04\x04\x04";//this adds a zero to the end
  size_t unpadded_len = 0;

  int r = pkcs7_unpad(buf,sizeof(buf)-1,16,&unpadded_len);
  ASSERT_EQ(0,r);
  ASSERT_EQ(12,unpadded_len);
}

TEST(pkcs7, check_wrong_pad) {
  uint8_t buf[] = "ICE ICE BABY\x05\x05\x05\x05";//this adds a zero to the end
  size_t unpadded_len = 0;

  int r = pkcs7_unpad(buf,sizeof(buf)-1,16,&unpadded_len);
  ASSERT_EQ(-1,r);

  uint8_t buf2[] = "ICE ICE BABY\x01\x02\x03\x04";//this adds a zero to the end

  r = pkcs7_unpad(buf,sizeof(buf)-1,16,&unpadded_len);
  ASSERT_EQ(-1,r);

}
