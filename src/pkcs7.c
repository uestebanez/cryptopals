#include "pkcs7.h"




int pkcs7_pad(uint8_t* buffer,size_t bufsiz,size_t bytesno,size_t blklen)
{
  if( NULL == buffer )
    return -1;

  if( blklen == 0 )
    return 0;

  
  size_t pad = pkcs7_needed_pad(bytesno,blklen);
  size_t i;

  if( bufsiz < bytesno + pad ) 
    return -1;

  for( i = 0; i < pad; i++ ) {
    buffer[bytesno+i] = pad;
  }
  return pad;
}

int pkcs7_unpad(uint8_t* buffer,size_t len,size_t blklen,size_t* unpadded_len)
{
  if (buffer == NULL || unpadded_len == NULL) {
    return -1;
  }

  if (len == 0 || blklen == 0) {
    return -1;
  }

  uint8_t pad = buffer[len - 1];

  if (pad == 0 || pad > blklen) {
    return -1;
  }

  if (pad > len) {
    return -1;
  }

  for (size_t i = 0; i < pad; i++) {
    if (buffer[len - 1 - i] != pad) {
      return -1;
    }
  }

  *unpadded_len = len - pad;
  return 0;
}
