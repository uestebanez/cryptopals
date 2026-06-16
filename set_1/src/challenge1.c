#include <stdio.h>
#include <string.h>
#include "base64.h"

#define TEST_STRING (const char*)"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
#define BASE64_EXPECTED (const char*)"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


int main(int argc,char** argv)
{
  char base64[4*(unsigned)ceil(strlen(TEST_STRING)/3.0)];

  int r = str2base64(TEST_STRING,base64);
  printf("%s\n",base64);
  return r;
}



