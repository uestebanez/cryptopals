#define _GNU_SOURCE // for memmem
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include "aes128.h"
#include "random.h"
#include "print.h"
#include "pkcs7.h"


static uint8_t g_key[AES128_BYTES_IN_BLK];
static uint8_t g_iv[AES128_BYTES_IN_BLK]={0};

static 
int encrypt_userdata(const uint8_t* input,size_t input_len,
                     uint8_t* cipher,size_t cipher_size,
                     size_t* cipher_len)
{
  static const char* prefix = "comment1=cooking%20MCs;userdata=";
  static const char* suffix = ";comment2=%20like%20a%20pound%20of%20bacon";

  if( NULL == input || NULL == cipher || NULL == cipher_len )
    return -1;

  size_t preflen = strlen(prefix);
  size_t suflen = strlen(suffix);
  uint8_t plain[preflen+input_len+suflen+AES128_BYTES_IN_BLK];
  size_t wr,rd;
  
  memcpy(plain,prefix,preflen);
  for( wr = preflen,rd=0; rd < input_len; rd++,wr++ ) {
    if( input[rd] == ';' ) {
      plain[wr] = '?';
    } else if ( input[rd] == '=' ) {
      plain[wr] = '_';
    } else {
      plain[wr] = input[rd];
    }
  }
  memcpy(&plain[wr],suffix,suflen);
  wr+=suflen;
  int pad = pkcs7_pad(plain,sizeof(plain),wr,AES128_BYTES_IN_BLK);
  wr+=pad;
  return aes128_cbc_encrypt(plain,wr,g_key,g_iv,cipher,cipher_size,cipher_len);
}

static 
bool is_admin(const uint8_t* cipher,size_t cipher_len)
{
  int r;
  uint8_t plain[512];
  size_t plain_len = 0;
  static const uint8_t admin[]=";admin=true;";

  r = aes128_cbc_decrypt(cipher,cipher_len,g_key,g_iv,plain,sizeof(plain),
                         &plain_len);
  if( 0 != r ) {
    printf("Error decrypting\n");
    return false;
  }
  r = pkcs7_unpad(plain,plain_len,AES128_BYTES_IN_BLK,&plain_len);
  if( -1 == r ) {
    printf("Error unpadding\n");
    return false;
  }
  printf("[%.*s]\n",(int)plain_len,plain);
  if( NULL == memmem(plain,plain_len,admin,sizeof(admin)-1) ) 
    return false;
  return true;
}

int main(int argc,char** argv)
{
  uint8_t user_data[] = ";admin=true;";
  uint8_t cipher[512];
  size_t cipher_len = 0;
  int r;

  assert(0==random_bytes(g_key,sizeof(g_key)));
  r = encrypt_userdata(user_data,sizeof(user_data)-1,cipher,sizeof(cipher),
                       &cipher_len);
  if( r != 0 ) {
    printf("Error encrypting user data\n");
    return -1;
  }
  printf("Before attack\n");
  if( is_admin(cipher,cipher_len) ) {
    printf("Admin detected!!!\n");
  } else {
    printf("No admin detected\n");
  }
  cipher[16] ^= ';' ^ '?';
  cipher[16+6] ^= '=' ^ '_';
  cipher[16+11] ^= ';' ^ '?';

  printf("After attack\n");
  if( is_admin(cipher,cipher_len) ) {
    printf("Admin detected!!!\n");
  } else {
    printf("No admin detected\n");
  }
  return 0;
}

