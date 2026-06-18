#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "base64.h"
#include "convert.h"

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

static uint8_t base642byte(char c)
{
  if ( c >= 'A' && c <= 'Z' ) {
    return c - 'A';
  } else if ( c >= 'a' && c <= 'z' ) {
    return c - 'a' + 26;
  } else  if ( c >= '0' && c <= '9' ) {
    return c - '0' + 52;
  } else {
    switch(c) {
      case '+': return 62;
      case '/': return 63;
    }
  }
  return 255;
}

int str2base64(const char* str,char* b64)
{
  uint8_t* buf;
  if( NULL == str || NULL == b64 )
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

int base642str(const char* b64,char* str)
{
  if( NULL == b64 || NULL == str )
    return -1;

  size_t len = strlen(b64);
  if( len < 4 )
    return -2;

  size_t i = 0;
  char c1,c2,c3,c4;
  uint8_t bytes[4];
  size_t widx=0;
  // block of 4 base64 chars
  while(b64[i] != '\0') {
    c1 = b64[i++];
    c2 = b64[i++];
    c3 = b64[i++];
    c4 = b64[i++];
    if( c3 == '=' && c4 == '=' ) { // 1 byte
      bytes[0] = base642byte(c1);
      bytes[1] = base642byte(c2);
      bytes[0] <<= 2;
      bytes[0] |= bytes[1] >> 4;
      str += bytes2hex_ascii(bytes,1,str) * 2;
    } else  if ( c4 == '=' ) {// 2 bytes
      bytes[0] = base642byte(c1);
      bytes[1] = base642byte(c2);
      bytes[2] = base642byte(c3);
      bytes[0] <<= 2;
      bytes[0] |= (bytes[1] >> 4);
      bytes[1] = (bytes[1] & 0x0F) << 4;
      bytes[1] |= bytes[2] >> 2;
      str += bytes2hex_ascii(bytes,2,str) * 2;
    } else { // 3 bytes
      bytes[0] = base642byte(c1);
      bytes[1] = base642byte(c2);
      bytes[2] = base642byte(c3);
      bytes[3] = base642byte(c4);
      bytes[0] <<= 2;
      bytes[0] |= (bytes[1] >> 4);
      bytes[1] = (bytes[1] & 0x0F) << 4;
      bytes[1] |= bytes[2] >> 2;
      bytes[2] &= 0x03;         
      bytes[2] <<= 6;
      bytes[2] |= bytes[3] & 0x3F;
      str += bytes2hex_ascii(bytes,3,str) * 2;
    }
  }
  return 0;
}




