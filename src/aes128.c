#include <string.h>
#include <openssl/evp.h>
#include "aes128.h"

int aes128_check_repeated_blocks(const uint8_t* bytes,size_t len,size_t blksiz)
{
  size_t blocks = len / blksiz;
  size_t i,j;
  int score = 0;

  for( i = 0; i < blocks; i++ ) {
    for( j = i+1; j < blocks; j++ ) {
      if( 0 == memcmp(&bytes[i*blksiz],&bytes[j*blksiz],blksiz) ) {
        score++;
      }
    }
  }
  return score;
}

int aes128_ecb_encrypt(const uint8_t* plain,
                       size_t plain_len,
                       const uint8_t key[16],
                       uint8_t* ciphered,
                       size_t ciphered_size,
                       size_t* ciphered_len)
{
  int r=0;

  if( NULL == plain || NULL == ciphered || NULL == ciphered_len ) {
    printf("wrong params\n");
    return -1;
  }

  if( ciphered_size < plain_len ) {
    printf("ciphered size < plain_len\n");
    return -1;
  }

  if( plain_len % 16 != 0 ) {
    printf("plain len is not multiple of 16\n");
    return -1;
  }

  *ciphered_len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if( NULL == ctx )
    return -1;

  r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
  if( r!=1 )
    goto end;
  
  r = EVP_CIPHER_CTX_set_padding(ctx, 0);
  if( r!=1 )
    goto end;

  int outl=0;
  r = EVP_EncryptUpdate(ctx, ciphered, &outl, plain, (int)plain_len);
  if( r!=1 ) {
    printf("Error updating\n");
    goto end;
  }
  *ciphered_len += (size_t)outl;
  r = EVP_EncryptFinal_ex(ctx, &ciphered[*ciphered_len], &outl);
  if( r!= 1 )
    goto end;
  *ciphered_len += (size_t)outl;

end:
  EVP_CIPHER_CTX_free(ctx);
  return r == 1 ? 0 : -1;
}

int aes128_cbc_encrypt(const uint8_t* plain,
                       size_t plain_len,
                       const uint8_t key[16],
                       const uint8_t iv[16],
                       uint8_t* ciphered,
                       size_t ciphered_size,
                       size_t* ciphered_len)
{
  int r=0;

  if( NULL == plain || NULL == ciphered || NULL == ciphered_len ) {
    printf("wrong params\n");
    return -1;
  }

  if( ciphered_size < plain_len ) {
    printf("ciphered size < plain_len\n");
    return -1;
  }

  if( plain_len % 16 != 0 ) {
    printf("plain len is not multiple of 16\n");
    return -1;
  }

  *ciphered_len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if( NULL == ctx )
    return -1;

  r = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
  if( r!=1 )
    goto end;
  
  r = EVP_CIPHER_CTX_set_padding(ctx, 0);
  if( r!=1 )
    goto end;

  int outl=0;
  r = EVP_EncryptUpdate(ctx, ciphered, &outl, plain, (int)plain_len);
  if( r!=1 ) {
    printf("Error updating\n");
    goto end;
  }
  *ciphered_len += (size_t)outl;
  r = EVP_EncryptFinal_ex(ctx, &ciphered[*ciphered_len], &outl);
  if( r!= 1 )
    goto end;
  *ciphered_len += (size_t)outl;

end:
  EVP_CIPHER_CTX_free(ctx);
  return r == 1 ? 0 : -1;

}

int aes128_detect_ecb_cbc(const uint8_t* ciphered,size_t ciphered_len)
{
  if( NULL == ciphered )
    return -1;

  if( ciphered_len % 16 != 0 )
    return -1;

  int score = aes128_check_repeated_blocks(ciphered,ciphered_len,16);
  if( score > 0 ) {
    return AES128_ECB_MODE;
  } else {
    return AES128_CBC_MODE;
  }

}
