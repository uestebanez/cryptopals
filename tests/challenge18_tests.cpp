#include <cstdlib>
#include <gtest/gtest.h>
#include "aes128.h"
#include "print.h"
#include "base64.h"

TEST(crt_mode, wrong_input) {
  int r = aes128_ctr_crypt(NULL,0,NULL,0,NULL,0,NULL);
  ASSERT_EQ(-1,r);
}

TEST(crt_mode, right_input) {
  const uint8_t str[] = "Hola mundo";
  size_t clen = 0,plen = 0;
  uint8_t ciphered[256];
  uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
  uint8_t plain[256];
  
  int r = aes128_ctr_crypt(str,sizeof(str)-1,key,0,ciphered,
                           sizeof(ciphered),&clen);  
  ASSERT_EQ(0,r);
  r = aes128_ctr_crypt(ciphered,sizeof(str)-1,key,0,plain,
                           sizeof(plain),&plen);  
  ASSERT_EQ(0,r);
  ASSERT_EQ(0,memcmp(plain,str,plen));

}

TEST(crt_mode, challenge_input) {
  const char* str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
  const uint8_t key[] = "YELLOW SUBMARINE";
  uint8_t plain[256];
  uint8_t ciphered[256];
  size_t plen = 0,clen;
  const char* expected = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";

  ASSERT_EQ(0,base642bin(str,ciphered));
  clen = base64_binsize(str);
  int r = aes128_ctr_crypt(ciphered,clen,key,0,plain,
                           sizeof(plain),&plen);  
  ASSERT_EQ(0,r);
  ASSERT_EQ(strlen(expected),plen);
  ASSERT_EQ(0,memcmp(plain,expected,plen));
}

