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

void print_bytes(FILE* file,const uint8_t* bytes,size_t len,const char* prefix)
{
  if( prefix != NULL )
    fprintf(file,"%s",prefix);
  for(; len > 0; len--) {
    fprintf(file,"%02"PRIX8,*bytes++);
  }
  fprintf(file,"\n");
}

void print_bytes_as_ascii(FILE* file,const uint8_t* bytes,
                          size_t len,const char* prefix,
                          const char* suffix)
{
  if( prefix != NULL )
    fprintf(file,"%s",prefix);
  for(; len > 0; len--,bytes++) {
    fprintf(file,"%c",isprint(*bytes) ? *bytes : '.');    
  }
  if( suffix )
    fprintf(file,"%s",suffix);
  fprintf(file,"\n");

}


