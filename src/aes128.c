#include <string.h>
#include <openssl/evp.h>
#include <endian.h>
#include "aes128.h"
#include "fixed_xor.h"

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

int aes128_ecb_decrypt(const uint8_t* ciphered,
                       size_t ciphered_len,
                       const uint8_t key[16],
                       uint8_t* plain,
                       size_t plain_size,
                       size_t* plain_len)
{
  int r = 0;

  if( NULL == ciphered || NULL == plain || NULL == plain_len ) {
    printf("wrong params\n");
    return -1;
  }

  if( plain_size < ciphered_len ) {
    printf("plain size < ciphered_len\n");
    return -1;
  }

  if( ciphered_len % 16 != 0 ) {
    printf("ciphered len is not multiple of 16\n");
    return -1;
  }

  *plain_len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if( NULL == ctx )
    return -1;

  r = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
  if( r != 1 )
    goto end;

  r = EVP_CIPHER_CTX_set_padding(ctx, 0);
  if( r != 1 )
    goto end;

  int outl = 0;

  r = EVP_DecryptUpdate(ctx, plain, &outl, ciphered, (int)ciphered_len);
  if( r != 1 ) {
    printf("Error updating\n");
    goto end;
  }

  *plain_len += (size_t)outl;

  r = EVP_DecryptFinal_ex(ctx, &plain[*plain_len], &outl);
  if( r != 1 )
    goto end;

  *plain_len += (size_t)outl;

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

int aes128_cbc_decrypt(const uint8_t* ciphered,
                       size_t ciphered_len,
                       const uint8_t key[16],
                       const uint8_t iv[16],
                       uint8_t* plain,
                       size_t plain_size,
                       size_t* plain_len)
{
  int r = 0;

  if (NULL == ciphered || NULL == plain || NULL == plain_len) {
    printf("wrong params\n");
    return -1;
  }

  if (plain_size < ciphered_len) {
    printf("plain size < ciphered_len\n");
    return -1;
  }

  if (ciphered_len == 0 || ciphered_len % 16 != 0) {
    printf("ciphered len is not multiple of 16\n");
    return -1;
  }

  *plain_len = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (NULL == ctx) {
    return -1;
  }

  r = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
  if (r != 1) {
    goto end;
  }

  r = EVP_CIPHER_CTX_set_padding(ctx, 0);
  if (r != 1) {
    goto end;
  }

  int outl = 0;

  r = EVP_DecryptUpdate(ctx,
                        plain,
                        &outl,
                        ciphered,
                        (int)ciphered_len);
  if (r != 1) {
    printf("Error updating\n");
    goto end;
  }

  *plain_len += (size_t)outl;

  r = EVP_DecryptFinal_ex(ctx, &plain[*plain_len], &outl);
  if (r != 1) {
    goto end;
  }

  *plain_len += (size_t)outl;

end:
  EVP_CIPHER_CTX_free(ctx);
  return r == 1 ? 0 : -1;
}

int aes128_ctr_crypt(const uint8_t* input,
                     size_t input_len,
                     const uint8_t key[16],
                     uint64_t nonce,
                     uint8_t* output,
                     size_t output_capacity,
                     size_t* output_len)
{
  uint64_t counter = 0;
  uint8_t block[AES128_BYTES_IN_BLK];
  uint8_t key_stream[AES128_BYTES_IN_BLK];
  size_t ciphered_len = 0;
  size_t rd=0;
  size_t wr=0;
  int r;

  if( input == NULL || NULL == key || NULL == output || NULL == output_len )
    return -1;

  if( output_capacity < input_len )
    return -1;

  uint64_t lend = htole64(nonce);
  memcpy(block,&lend,8);
  while( input_len > 0 ) {
    size_t bytes2xor;
    uint64_t bend = htole64(counter);
    memcpy(&block[8],&bend,8);

    r = aes128_ecb_encrypt(block,AES128_BYTES_IN_BLK,
                           key,key_stream,AES128_BYTES_IN_BLK,
                           &ciphered_len);
    if( r != 0 || ciphered_len != AES128_BYTES_IN_BLK )
      return r;

    if( input_len >= AES128_BYTES_IN_BLK ) {
      bytes2xor = AES128_BYTES_IN_BLK;
    } else {
      bytes2xor = input_len;
    }
    fixed_xor_bin(&input[rd],key_stream,bytes2xor,&output[wr]);
    rd+=bytes2xor;
    wr+=bytes2xor;
    input_len-=bytes2xor;
    counter++;
  }
  *output_len = wr;
  return 0;
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
