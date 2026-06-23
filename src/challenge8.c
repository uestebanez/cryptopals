#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "convert.h"
#include "print.h"
#include "aes128.h"

#define LINE_SIZE 60

int main(int argc,char** argv)
{
  FILE* file;

  if( argc < 2 ) {
    printf("I need a file to parse\n");
    return -1;
  }
  file = fopen(argv[1],"r");
  if( NULL == file ) {
    printf("Failure opening the file\n");
    return -2;
  }
  
  size_t llen; // line len
  char* line=NULL;
  size_t lineno=0;
  uint8_t* raw_bytes = NULL;

  while(getline(&line,&llen,file) > 0 ) {
    lineno++;
    line[strcspn(line, "\n")] = '\0';
    llen = strlen(line);
    size_t bytesno = str2bytes(line,&raw_bytes);
    //print_bytes(stdout,raw_bytes,bytesno,"buf:");
    //printf("bytesno=%zu llen=%zu\n",bytesno,llen);
    int score = aes128_check_repeated_blocks(raw_bytes,bytesno,16);
    if( score > 0 ) {
      printf("Score for line %zu is %d\n",lineno,score);
    }
    free(line);
    line = NULL;
    llen = 0;
    free(raw_bytes);
    raw_bytes = NULL;
  }
  
   
end:
  fclose(file);
  return 0;
}
