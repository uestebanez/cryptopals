#include "random.h"
#include <openssl/rand.h>


int random_bytes(uint8_t* buffer, size_t len)
{
  if( NULL == buffer )
    return -1;
  if( 0 == len )
    return 0;

  if( 1 != RAND_bytes(buffer, len) )
    return -1;
  
  return 0;
}

int random_range(size_t min, size_t max, size_t* out)
{
  if( NULL == out )
    return -1;
  if( max < min )
    return -1;

  size_t range = max - min + 1;
  *out = min + (rand() % range);
  return 0;
}
