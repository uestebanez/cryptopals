#include "hamming.h"

static size_t hamming_dist_byte(uint8_t a,uint8_t b)
{
  uint8_t i,mask = 0x01;
  size_t distance = 0;
  
  for( i = 0; i < 8; i++ ) {
    if( (a & mask) != (b & mask) ) 
      distance++;
    mask <<= 1;
  }
  return distance;
}

size_t hamming_distance(const uint8_t* a,const uint8_t* b,size_t len)
{
  size_t i,distance = 0;

  for( i = 0; i < len; i++ ) 
    distance  += hamming_dist_byte(*a++,*b++);
  return distance;
}
