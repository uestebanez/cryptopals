#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include "base64.h"
#include "fixed_xor.h"
#include "score.h"
#include "convert.h"
#include "print.h"

#define LINE_SIZE 60


int main(int argc,char** argv)
{
  FILE* file;
  int score;
  int max_score = -1;
  char line[LINE_SIZE+2];
  char candidate_line[LINE_SIZE+1];
  char deciphered[LINE_SIZE+1];

  if( argc < 2 ) {
    printf("I need a file to parse\n");
    return -1;
  }
  file = fopen(argv[1],"r");
  if( NULL == file ) {
    printf("Failure opening the file\n");
    return -2;
  }
  while(NULL != fgets(line,sizeof(line),file) ) {
    line[strcspn(line, "\n")] = '\0';
    score = fixed_xor_try(line,deciphered,NULL);
    if( score > max_score ) {
      max_score = score;
      strcpy(candidate_line,deciphered);
    }
  }
  printf("candidate=[");
  print_hex_as_ascii(candidate_line);
  printf("] score:%d\n",max_score);
  fclose(file);
  return 0;
}
