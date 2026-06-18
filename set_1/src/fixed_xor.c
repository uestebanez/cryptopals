#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "fixed_xor.h"
#include "base64.h"
#include "convert.h"


int fixed_xor(const char* input,const char* key, char* output)
{
  if( NULL == input || NULL == key || NULL == output )
    return -1;

  size_t len = strlen(input);
  if( len % 2 != 0 )
    return -2;

  char input_aux[3];
  char key_aux[3];
  uint8_t *input_byte;
  uint8_t *key_byte;
  size_t i;
  for( i = 0; i < len; i+=2 ) {
    input_aux[0] = input[i];
    input_aux[1] = input[i+1];
    input_aux[2] = 0;
    key_aux[0] = key[i];
    key_aux[1] = key[i+1];
    key_aux[2] = 0;

    str2bytes((const char*)input_aux,&input_byte);
    str2bytes((const char*)key_aux,&key_byte);
    uint8_t xor = *input_byte ^ *key_byte;
    sprintf(output,"%02x",xor);
    output+=2;
  }
  return 0;
}
