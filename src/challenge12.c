#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "print.h"
#include "pkcs7.h"
#include "aes128.h"
#include "base64.h"
#include "random.h"

static uint8_t g_key[AES128_BYTES_IN_BLK];

static const char* g_unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0a"
                                       "CBteSByYWctdG9wIGRvd24gc28gbX"
                                       "kgaGFpciBjYW4gYmxvdwpUaGUgZ2l"
                                       "ybGllcyBvbiBzdGFuZGJ5IHdhdmlu"
                                       "ZyBqdXN0IHRvIHNheSBoaQpEaWQge"
                                       "W91IHN0b3A/IE5vLCBJIGp1c3QgZH"
                                       "JvdmUgYnkK";

/**
 * \brief do following steps:
 * 1 - input || unknown-string
 * 2 - Padding
 * 3 - Ecncrypt
 * \param input buffer with the input
 * \param input_len length of the input
 * \param output output buffer
 * \param output_size capacity of the output buffer
 * \param output_len filled bytes in output buffer
 * \return 0 if success, -1 if error
 */
static int encryption_oracle(const uint8_t* input,
                      size_t input_len,
                      uint8_t* output,
                      size_t output_size,
                      size_t* output_len)
{
  int r=0;

  if( NULL == output || NULL == output_len )
    return -1;

  size_t binsiz = base64_binsize(g_unknown_string);
  uint8_t* bin = malloc(binsiz);
  if ( NULL == bin )
    return -1;

  if ( 0 != base642bin(g_unknown_string,bin) ) {
    r = -1;
    goto end;
  }

  size_t plainsiz = binsiz+input_len+AES128_BYTES_IN_BLK;
  uint8_t* plain = malloc(plainsiz);
  if( NULL == plain ) {
    r = -1;
    goto end;
  }
  memcpy(plain,input,input_len);
  memcpy(&plain[input_len],bin,binsiz);
  int pad = pkcs7_pad(plain,plainsiz,binsiz+input_len,AES128_BYTES_IN_BLK);
  if( -1 == pad ) {
    r = -1;
    goto end;
  }
  size_t plain_len = binsiz+input_len+pad;
  if( 0 != aes128_ecb_encrypt(plain,plain_len,g_key,output,output_size,
                              output_len) ) {
    r = -1;
    goto end;
  }

end:
  if( bin )
    free(bin);  
  if ( plain )
    free(plain);
  return r;
}

static size_t detect_blk_size(void)
{
  uint8_t input[128];
  uint8_t output[AES128_BYTES_IN_BLK*10];
  size_t blksiz;
  size_t base;
  size_t output_len=0;

  // call to the oracle with empty input to get a base size 
  assert(0==encryption_oracle(NULL,0,output,sizeof(output),
                              &output_len));
  base = output_len;
  size_t i;
  for(i = 1; i < 128; i++ ) {
    memset(input,'A',i);
    output_len = 0;
    assert(0==encryption_oracle(input,i,output,sizeof(output),
                                &output_len));
    /* when output size changes is because another block is needed and we
       can find the block size */
  if( output_len > base ) { 
      blksiz = output_len - base;
      break;
    }
  }
  return blksiz;

}

static bool detect_ecb(size_t blksiz)
{
  uint8_t input[blksiz*4];
  uint8_t output[AES128_BYTES_IN_BLK*100];
  size_t output_len=0;

  memset(input,'A',sizeof(input));
  assert(0==encryption_oracle(input,sizeof(input),output,sizeof(output),
                               &output_len));
  int r = aes128_detect_ecb_cbc(output,output_len);
  if( r != AES128_ECB_MODE )
    return false;
  else
    return true;

}

int main(int argc,char** argv)
{
  uint8_t input[AES128_BYTES_IN_BLK];
  uint8_t output[AES128_BYTES_IN_BLK*10];
  size_t output_len = 0;
  size_t blksiz;
  int r;

  assert(0==random_bytes(g_key,sizeof(g_key)));
  blksiz = detect_blk_size();
  printf("block size is %zu\n",blksiz);

  if( detect_ecb(blksiz) == false ) {
    printf("ECB not detected\n");
    return -1;
  }
  printf("ECB detectec\n");

  /*
  memset(input,'A',AES128_BYTES_IN_BLK-1);
  print_bytes(stdout,input,AES128_BYTES_IN_BLK-1,"input:"); 
  assert(0==encryption_oracle(input,AES128_BYTES_IN_BLK-1,output,sizeof(output),
                    &output_len));
  print_bytes(stdout,output,output_len,"output:"); 
  */
  return 0;
}


