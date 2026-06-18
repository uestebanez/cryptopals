#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include "base64.h"
#include "hamming.h"

#define LINE_SIZE 60


int main(int argc,char** argv)
{
  FILE* file;
  char line[LINE_SIZE+2];

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
  size_t textsiz = 0;
  char* text=NULL;

  while(NULL != fgets(line,sizeof(line),file) ) {
    line[strcspn(line, "\n")] = '\0';
    llen = strlen(line);
    text = realloc(text,llen+textsiz);
    strcat(text,line);
    textsiz+=llen;
  }
  size_t binsiz = base64_binsize(text);
  uint8_t* bin = calloc(1,binsiz);
  base642bin(text,bin);
  double best_dist = 999.0; 
  size_t keysiz;
  size_t best_keysiz;
  for( keysiz = 2; keysiz < 40; keysiz++ ) {// I pick up to 40 keysiz
    size_t blocks = binsiz / keysiz; // I'll discard the remaining of division
    size_t b;                              
    double normalized_dist = 0;
    for( b = 0; b < blocks; b++ ) {
      size_t dist = hamming_distance(&bin[keysiz*b],&bin[keysiz*b+keysiz],keysiz);
      normalized_dist += (double)dist / (double)keysiz;
    }
    double avg_norm_dist = normalized_dist/blocks;
    if( avg_norm_dist < best_dist ) {
      best_dist = avg_norm_dist;
      best_keysiz = keysiz;
    }
  }
  printf("Best distance is:%lf distance:%zu\n",best_dist,best_keysiz);

  free(text);
  free(bin);
  fclose(file);
  return 0;
}
