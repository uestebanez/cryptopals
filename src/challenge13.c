#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "aes128.h"
#include "random.h"
#include "print.h"
#include "pkcs7.h"


static uint8_t g_key[AES128_BYTES_IN_BLK];

static char* profile_for(const char* email,size_t* prof_siz)
{
  if( NULL == email || prof_siz == NULL )
    return NULL;

  size_t elen = strlen(email);
  // len 6 -> email=
  // len 17 -> &uid=10&role=user
  size_t total_siz = 6+elen+17+1;

  char* find = strpbrk(email,"&=");
  if( NULL != find ) {
    printf("Found illegal chars '&' or '='\n");
    return NULL;
  }
  char* buf = malloc(total_siz);
  *prof_siz = total_siz;
  snprintf(buf,total_siz,"email=%s&uid=10&role=user",email);
  return buf;
}

static 
int encrypt_profile(const char* profile, uint8_t* ciphered,size_t capacity,
                    size_t *clen)
{
  uint8_t* clear;

  size_t len = strlen(profile);
  size_t toalloc = (len / AES128_BYTES_IN_BLK)*AES128_BYTES_IN_BLK;
  toalloc += len % AES128_BYTES_IN_BLK;
  toalloc += AES128_BYTES_IN_BLK - (len % AES128_BYTES_IN_BLK);

  clear = malloc(toalloc);
  memcpy(clear,profile,len);
  int pad = pkcs7_pad(clear,toalloc,len,AES128_BYTES_IN_BLK);
  int r = aes128_ecb_encrypt(clear,toalloc,g_key,
                     ciphered,capacity,clen);
  free(clear);
  return r;

}

int main(int argc,char** argv)
{
  char* profile;
  size_t prof_siz;
  uint8_t ciphered[256];
  uint8_t ciphered2[256];
  uint8_t plain[256];
  size_t clen = 0;
  size_t clen2 = 0;
  size_t dlen = 0;
  size_t plen = 0;
  
  assert(0==random_bytes(g_key,sizeof(g_key)));

  // 13 'A' + "email=" -> 19
  // 19 + "&uid=10&role=" (13chars) -> 32 chars
  profile = profile_for("AAAAAAAAAAAAA",&prof_siz);

  //email=AAAAAAAAAAAAA&uid=10&role= -> 32 bytes
  //user -> last block of 4 bytes
  printf("profile=[%s]\n",profile);
  encrypt_profile(profile,ciphered,sizeof(ciphered),&clen);
  print_bytes(stdout,ciphered,clen,"Ciphered profile:");
  free(profile);

  aes128_ecb_decrypt(ciphered,clen,g_key,plain,sizeof(plain),&dlen);
  if( 0 != pkcs7_unpad(plain,dlen,AES128_BYTES_IN_BLK,&plen) ) {
    printf("Error in padding\n");
    return -1;
  }
  // be carefull with the end '\0', could be not present 
  printf("deciphered:[%.*s]\n",(int)plen,plain); 
  
  uint8_t buf[]={'A','A','A','A','A','A','A','A','A','A',
                 'a','d','m','i','n',
                 0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x00};

  profile = profile_for(buf,&prof_siz);
  encrypt_profile(profile,ciphered2,sizeof(ciphered2),&clen2);
  free(profile);
  print_bytes(stdout,ciphered2,clen2,"Ciphered profile:");
  
  // in first block we will find the "admin"  
  memcpy(&ciphered[clen-AES128_BYTES_IN_BLK],&ciphered2[AES128_BYTES_IN_BLK],
         AES128_BYTES_IN_BLK);

  aes128_ecb_decrypt(ciphered,clen,g_key,plain,sizeof(plain),&dlen);
  if( 0 != pkcs7_unpad(plain,dlen,AES128_BYTES_IN_BLK,&plen) ) {
    printf("Error in padding\n");
    return -1;
  }
  // be carefull with the end '\0', could be not present 
  printf("deciphered:[%.*s]\n",(int)plen,plain); 


  return 0;
}
