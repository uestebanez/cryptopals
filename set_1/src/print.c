#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <inttypes.h>
#include "convert.h"
#include "print.h"


void print_hex_as_ascii(const char* hex)
{
  size_t i = 0;
  char aux[3];
  while(hex[i] != 0 ) {
    aux[0] = hex[i];
    aux[1] = hex[i+1];
    aux[2] = 0;
    char ascii = hex2bin(aux);
    if( isalpha(ascii) || isdigit(ascii) || isblank(ascii) )
      printf("%c",(char)ascii);
    i+=2;
  }
}

void print_bytes(FILE* file,const uint8_t* bytes,size_t len,char* prefix)
{
  if( prefix != NULL )
    fprintf(file,"%s",prefix);
  for(; len > 0; len--) {
    fprintf(file,"%"PRIX8,*bytes++);
  }
  fprintf(file,"\n");
}
