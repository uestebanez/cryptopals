#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "convert.h"

static char nibble2hexchar(uint8_t b)
{
  char c;

  if( b < 10 ) {
    c = '0' + b;
  } else if ( b >= 10 && b <= 15 ) {
    c = 'A' + (b - 10);
  }
  return c;
}

static void byte2ascii_hex(uint8_t b,char* output)
{
  uint8_t h = b >> 4;
  uint8_t l = b & 0x0F;
  *output++ = nibble2hexchar(h);
  *output = nibble2hexchar(l);
}

static void ascii_char2hex_ascii(const char ascii,char* hex)
{
  uint8_t h = ascii >> 4; // high part
  uint8_t l = ascii % 16; // low part
  hex[0] = nibble2hexchar(h);
  hex[1] = nibble2hexchar(l);
}

int ascii2hex_ascii(const char* ascii, char* hex_ascii)
{
  size_t l = strlen(ascii);
  size_t i,j;
  for( i = 0,j=0; i < l; i++,j+=2 ) {
    ascii_char2hex_ascii(ascii[i],&hex_ascii[j]);
  }
  hex_ascii[j] = '\0';
  return i;
}

size_t str2bytes(const char* str,uint8_t** bytes)
{
  size_t l = strlen(str);
  size_t i,wr_idx = 0;
  char aux[3]; // auxiliar to convert hex to bin               

  if ( l == 0 || (l % 2 != 0) ) // buffer must have complete bytes
    return 0;

  uint8_t* buf = calloc(1,l/2);
  if( buf == NULL )
    return 0;

  for( i = 0; i < l; i+=2 ) {
    aux[0] = str[i];
    aux[1] = str[i+1];
    aux[2] = 0;
    sscanf(aux,"%hhx",&buf[wr_idx++]);
  }
  *bytes = buf;
  return l/2;
}

size_t bytes2hex_ascii(const uint8_t* buf,size_t len,char* output)
{
  size_t i;
  if( NULL == buf || NULL == output )
    return 0;
  for( i = 0; i < len; i++,output+=2 ) {
    byte2ascii_hex(buf[i],output);
  }
  *output = 0;
  return i;
}
