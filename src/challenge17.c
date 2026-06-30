#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "random.h"
#include "aes128.h"
#include "base64.h"
#include "pkcs7.h"
#include "print.h"

#define MAX_ENTRIES 10

static uint8_t g_key[AES128_BYTES_IN_BLK];

static const char* g_strings[MAX_ENTRIES] = { 
"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};

static int encryption_oracle(uint8_t* iv,size_t iv_size,
                             uint8_t* cipher,size_t cipher_size,
                             size_t* cipher_len)
{
  size_t idx;
  int r = 0;

  if( -1 == random_range(0,9,&idx) )
    return -1;
  
  r = random_bytes(iv,iv_size);
  if( -1 == r ) 
    return -1;

  const char* str = g_strings[idx];
  printf("String choosen at position %zu is [%s]\n",idx,str);
  size_t psize = base64_binsize(str);

  size_t pad = pkcs7_needed_pad(psize,AES128_BYTES_IN_BLK);

  uint8_t* plain = malloc(psize+pad);
  if( NULL == plain ) {
    return -1;
  }
    
  if( 0 != base642bin(str,plain,NULL) ) {
    r = -1;
    goto end;
  }

  print_bytes_as_ascii(stdout,plain,psize,"Plain:",NULL);
  int p = pkcs7_pad(plain,psize+pad,psize,AES128_BYTES_IN_BLK);
  if( -1 == p ) {
    r = -1;
    goto end;
  }

  r = aes128_cbc_encrypt(plain,psize+pad,g_key,iv,
                         cipher,cipher_size,cipher_len);
  if( -1 == r ) {
    goto end;
  }

end:
  if( plain )
    free(plain);
  return r;
}


/**
 * \brief return 1 if the deciphered text has a valid padding
 * return 0 if not
 */
static int padding_oracle(const uint8_t* iv,
                         const uint8_t* cipher,
                         size_t cipher_len)
{
  uint8_t plain[512];
  size_t plen = 0;
  size_t unpadded_len = 0;
  int r;

    if (iv == NULL || cipher == NULL) {
        return 0;
    }
    if (cipher_len == 0 || cipher_len % AES128_BYTES_IN_BLK != 0) {
        return 0;
    }
    if (cipher_len > sizeof(plain)) {
        return 0;
    }

    r = aes128_cbc_decrypt(cipher,cipher_len,g_key,iv,plain,sizeof(plain),
                           &plen);
    if (r != 0) {
        return 0;
    }
    r = pkcs7_unpad(plain,plen,AES128_BYTES_IN_BLK,&unpadded_len);
    if (r != 0) {
        return 0;
    }
    return 1;
}

static 
int attack_block(const uint8_t previous_blk[AES128_BYTES_IN_BLK],
                 const uint8_t current_blk[AES128_BYTES_IN_BLK],
                 uint8_t plain[AES128_BYTES_IN_BLK])
                     
{
    uint8_t modified_blk[AES128_BYTES_IN_BLK];
    uint8_t deciphered[AES128_BYTES_IN_BLK] = {0}; // before the xor with previous block
    
    memcpy(modified_blk,previous_blk,AES128_BYTES_IN_BLK);
  
    for( int b = AES128_BYTES_IN_BLK - 1; b >= 0 ; b-- ) {
      uint8_t pad = AES128_BYTES_IN_BLK - b; // 0x01, 0x02, etc...
      
      for( int j = b + 1; j < AES128_BYTES_IN_BLK;j++ ) { 
        modified_blk[j] = deciphered[j] ^ pad;
      }
      for (int i = 0; i <= 255; i++) {
          modified_blk[b] = (uint8_t)i;

          if (padding_oracle(modified_blk,current_blk,AES128_BYTES_IN_BLK)) {
              deciphered[b] = ((uint8_t)i) ^ pad;
              plain[b] = deciphered[b] ^ previous_blk[b];
              break;
          }
      }

    }

    return 0;
}

static int attack(const uint8_t iv[AES128_BYTES_IN_BLK],
                  const uint8_t* ciphered,size_t clen,
                  uint8_t* plain,size_t capacity,size_t* plen)
{
  const uint8_t* previous = iv;

  if( capacity < clen )
    return -1;

  *plen = 0;
  for( int b = 0; b < clen / AES128_BYTES_IN_BLK; b++ ) {
    attack_block(previous,&ciphered[AES128_BYTES_IN_BLK*b],
                 &plain[AES128_BYTES_IN_BLK*b]);
    previous = &ciphered[AES128_BYTES_IN_BLK*b];
    *plen+=AES128_BYTES_IN_BLK;
  }
  return 0;
}

int main(int argc,char** argv)
{
  uint8_t ciphered[512];
  size_t clen=0;
  uint8_t iv[AES128_BYTES_IN_BLK];
  uint8_t plain[512];
  size_t plen=0;
  int r;

  srand((unsigned int)time(NULL));
  assert(0==random_bytes(g_key,sizeof(g_key)));
  
  r = encryption_oracle(iv,AES128_BYTES_IN_BLK,ciphered,sizeof(ciphered),
                        &clen);
  if( 0 != r )
  {
    printf("Error calling oracle\n");
    return r;
  }
  print_bytes(stdout,ciphered,clen,"Cipher text:");
  printf("clen=%zu\n",clen);
  attack(iv,ciphered,clen,plain,sizeof(plain),&plen);
  printf("plen=%zu\n",plen);
  print_bytes_as_ascii(stdout,plain,plen,"attacked plain:",NULL);
  size_t unpadded_len = 0;

  if (pkcs7_unpad(plain, plen, AES128_BYTES_IN_BLK, &unpadded_len) == 0) {
      print_bytes_as_ascii(stdout, plain, unpadded_len, "Recovered unpadded:",NULL);
  }
  return 0;
}

