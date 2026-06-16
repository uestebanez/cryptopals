#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "base64.h"

static const uint8_t g_base64_table[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
    'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9',
    '+', '/'
};

int str2base64(const char* str,char* b64)
{
  uint8_t* buf;
  if( NULL == str )
    return -1;

  unsigned int remaining_bytes;
  remaining_bytes = str2bytes(str,&buf);
  if( 0 == remaining_bytes )
    return -2;
  
  size_t rd_idx = 0,wr_idx=0;

  while( remaining_bytes >= 3 ) {
    uint8_t nibble1 = (buf[rd_idx] & 0xF0) >> 2;
    uint8_t nibble2 = (buf[rd_idx] & 0x0C) >> 2;
    uint8_t sixb = nibble1 | nibble2;
    b64[wr_idx++] = g_base64_table[sixb];
    nibble1 = (buf[rd_idx] & 0x03) << 4;
    nibble2 = (buf[rd_idx+1] & 0xF0) >> 4;
    sixb = nibble1 | nibble2;
    b64[wr_idx++] = g_base64_table[sixb];
    nibble1 = (buf[rd_idx+1] & 0x0F) << 2;
    nibble2 = (buf[rd_idx+2] & 0xC0) >> 6;
    sixb = nibble1 | nibble2;
    b64[wr_idx++] = g_base64_table[sixb];
    nibble1 = (buf[rd_idx+2] & 0x30);
    nibble2 = (buf[rd_idx+2] & 0x0F);
    sixb = nibble1 | nibble2;
    b64[wr_idx++] = g_base64_table[sixb];
    rd_idx += 3;
    remaining_bytes -= 3;
  }
  if( remaining_bytes == 1 ) {
    uint8_t sixb = (buf[rd_idx] & 0xFC) >> 2;
    uint8_t twob = (buf[rd_idx] & 0x03) << 6;
    b64[wr_idx++] = g_base64_table[sixb];
    b64[wr_idx++] = g_base64_table[twob];
    b64[wr_idx++] = '=';
    b64[wr_idx++] = '=';
    remaining_bytes--;
  }

  if( remaining_bytes == 2 ) {
    uint8_t sixb = (buf[rd_idx] & 0xFC) >> 2;
    uint8_t twob = (buf[rd_idx] & 0x03) << 4;
    b64[wr_idx++] = g_base64_table[sixb];
    rd_idx++;
    uint8_t fourb = (buf[rd_idx] & 0xF0)>>4;
    b64[wr_idx++] = g_base64_table[twob|fourb];
    fourb = (buf[rd_idx] & 0x0F)<<2;
    rd_idx++;
    b64[wr_idx++] = g_base64_table[fourb];
    b64[wr_idx++] = '=';
    remaining_bytes-=2;
  }
  free(buf);
  return 0;   
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
