#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "convert.h"

static char byte2char(uint8_t b)
{
  char c;

  if( b < 10 ) {
    c = '0' + b;
  } else if ( b >= 10 && b <= 15 ) {
    c = 'A' + (b - 10);
  }
  return c;
}

static void ascii_char2hex_ascii(const char ascii,char* hex)
{
  uint8_t h = ascii / 16; // high part
  uint8_t l = ascii % 16; // low part
  hex[0] = byte2char(h);
  hex[1] = byte2char(l);
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
