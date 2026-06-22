#include <openssl/evp.h>
#include "aes128.h"


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

