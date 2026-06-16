#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "base64.h"

char* str2base64(const char* str,char* b64)
{
  uint8_t* buf;
  buf = str2bytes(str);
  if( buf != NULL )
  {
    free(buf);
    buf = NULL;
  }
  return NULL;   
}


uint8_t* str2bytes(const char* str)
{
  size_t l = strlen(str);
  size_t i;
  char aux[3]; // auxiliar to convert hex to bin               

  if ( l % 2 != 0 ) // buffer must have complete bytes
    return NULL;

  uint8_t* buf = calloc(1,l/2);
  uint8_t* out = buf;

  if( buf == NULL )
    return buf;

  for( i = 0; i < l; i+=2 ) {
    aux[0] = str[i];
    aux[1] = str[i+1];
    aux[2] = 0;
    sscanf(aux,"%hhx",buf++);
  }
  return out;
}
