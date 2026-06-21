#include "pkcs7.h"

int pkcs7_pad(uint8_t* buffer,size_t bufsiz,size_t bytesno,size_t blklen)
{
  if( NULL == buffer )
    return -1;

  if( blklen == 0 )
    return 0;

  size_t pad = blklen - (bytesno % blklen);
  size_t i;

  if( bufsiz < bytesno + pad ) 
    return -1;

  for( i = 0; i < pad; i++ ) {
    buffer[bytesno+i] = pad;
  }
  return pad;
}
