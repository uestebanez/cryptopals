#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "repeating_xor.h"
#include "base64.h"
#include "convert.h"

int repeating_xor(const char* input,const char* key, char* output)
{
  if( NULL == input || NULL == key || NULL == output )
    return -1;

  size_t len = strlen(input);
  if( len % 2 != 0 )
    return -2;

  size_t key_len = strlen(key);
  if( key_len == 0 )
    return -2;

  char input_aux[3];
  char key_aux[3];
  uint8_t *input_byte;
  uint8_t *key_byte;
  size_t i,j;

  for( i = 0,j=0; i < len; i+=2,j+=2 ) {
    input_aux[0] = input[i];
    input_aux[1] = input[i+1];
    input_aux[2] = 0;
    key_aux[0] = key[j % key_len];
    key_aux[1] = key[(j+1) % key_len];
    key_aux[2] = 0;

    str2bytes((const char*)input_aux,&input_byte);
    str2bytes((const char*)key_aux,&key_byte);
    uint8_t xor = *input_byte ^ *key_byte;
    sprintf(output,"%02x",xor);
    output+=2;
  }

  return 0;
}
