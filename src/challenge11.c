#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include "print.h"
#include "pkcs7.h"
#include "aes128.h"

static int random_range(size_t min, size_t max, size_t* out)
{
  if( NULL == out )
    return -1;
  if( max < min )
    return -1;

  size_t range = max - min + 1;
  *out = min + (rand() % range);
  return 0;
}

static int get_prefix_suffix_len(size_t* pref_len,size_t* suf_len)
{
  if( 0 != random_range(5,10,pref_len) )
    return -1;
  if( 0 != random_range(5,10,suf_len) )
    return -1;
  return 0;
}

static int random_bytes(uint8_t* buffer, size_t len)
{
  if( NULL == buffer )
    return -1;
  if( 0 == len )
    return 0;

  if( 1 != RAND_bytes(buffer, len) )
    return -1;
  
  return 0;
}

static int build_plaintext(const uint8_t* input,
                                  size_t input_len,
                                  uint8_t* output,
                                  size_t output_size,
                                  size_t* output_len)
{
  if( NULL == input || NULL == output || NULL == output_len )
    return -1;

  size_t pref_len,suf_len;

  if( 0 != get_prefix_suffix_len(&pref_len,&suf_len) )
    return -2;

  if( output_size < pref_len+suf_len+input_len ) {
    return -3;
  }

  printf("Prefix len=%zu Suffix len=%zu\n",pref_len,suf_len);

  if( 0 != random_bytes(output,pref_len) )
    return -4;
  output+=pref_len;
  memcpy(output,input,input_len);
  output+=input_len;
  if( 0 != random_bytes(output,suf_len) ) 
    return -4;
  output+=suf_len;
  *output_len = input_len + pref_len + suf_len;
  return 0;
}

typedef enum {
  build_mode_ecb = 0,
  build_mode_cbc
}build_mode_t;

static 
int build_ciphertext(const uint8_t* input,size_t input_len,
                     uint8_t* output,size_t output_size,size_t* output_len,
                     build_mode_t *mode)
{
  uint8_t plain[input_len+10+10+16];
  size_t plain_len;

  print_bytes(stdout,input,input_len,"input bytes:");
  int r = build_plaintext(input,input_len,plain,sizeof(plain),&plain_len);
  if( 0 != r )
  {
    printf("Error %d building plaintext\n",r);
    return r;
  }
  printf("plain len=%zu\n",plain_len);
  int pad = pkcs7_pad(plain,sizeof(plain),plain_len,16);
  if( -1 == pad ) {
    printf("Error while padding\n");
    return -1;
  }
  plain_len+=pad;
  printf("Padding=%d bytes\n",pad);
  printf("new plain len=%zu\n",plain_len);
  print_bytes(stdout,plain,plain_len,"output bytes:");
  
  uint8_t key[16];
  if( 0 != random_bytes(key, sizeof(key)) ) 
  {
    return -1;
  }
  print_bytes(stdout,key,sizeof(key),"key:");

  random_range(build_mode_ecb,build_mode_cbc,(size_t*)mode);
  if( *mode == build_mode_ecb ) {
    printf("Mode ECB\n");
    if( -1 == aes128_ecb_encrypt(plain,plain_len,key,output,output_size,
                                 output_len) ) {
      printf("Error encrypting\n");
      return -1;
    }
    print_bytes(stdout,output,*output_len,"ECB:");
  } else if( *mode == build_mode_cbc ) {
    printf("Mode CBC\n");
  } else {
    printf("Wrong mode\n");
    return -1;
  }

  return r;
}

int main(int argc,char** argv)
{
  uint8_t input[] = {'H','O','L','A'};
  uint8_t output[256];
  size_t output_len = 0;
  build_mode_t mode;

  srand((unsigned int)time(NULL));
  build_ciphertext(input,sizeof(input),output,sizeof(output),&output_len,&mode);
  return 0;
}


