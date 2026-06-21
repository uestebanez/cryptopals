#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include "base64.h"
#include "hamming.h"
#include "fixed_xor.h"
#include "print.h"

#define LINE_SIZE 60


static size_t best_keysize(const uint8_t* bin,size_t binsiz)
{
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
  return best_keysiz;
}

/**
 * \brief fill a column wit transposed information from a binary buffer
 * \param bin binary buffer
 * \param cnum column number we want to get (0,1,...N)
 * \param keysiz size of each column
 * \param column buffer to store the column
 */
static 
void fill_column(const uint8_t* bin,size_t cnum,size_t keysiz,uint8_t* column)
{
  size_t i;

  for( i = 0; i < keysiz; i++ ) {
    column[i] = bin[i + (keysiz*cnum)];
  }
}

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
    text = realloc(text,llen+textsiz+1);
    strcat(text,line);
    textsiz+=llen;
  }
  size_t binsiz = base64_binsize(text);
  uint8_t* bin = calloc(1,binsiz);
  base642bin(text,bin);
  size_t best_keysiz = best_keysize(bin,binsiz); 
  printf("Best key size is:%zu\n",best_keysiz);

  size_t  column_size = binsiz / best_keysiz;
  size_t remainder = binsiz % best_keysiz;
  
  // some columns will have one more byte due to the remainder
  uint8_t* column = malloc(column_size+1); 
  
  uint8_t key[best_keysiz+1];// one more byte to print it as a string.
  size_t c,i;

  for( c = 0; c < best_keysiz; c++ ){
    size_t current_column_size;
    if( c < remainder )
      current_column_size = column_size + 1;
    else
      current_column_size = column_size;
    for( i = 0; i < current_column_size;i++ ) { // for each entry of the column
      column[i] = bin[c + i*best_keysiz];
    }
    fixed_xor_bin_try(column,current_column_size,&key[c]);
  }

  char* plain = calloc(binsiz+1,1);
  // try to decipher
  for( i = 0; i < binsiz; i++ ) {
    plain[i] = bin[i] ^ key[i % best_keysiz];
  }
  printf("Text:[%s]\n",plain);
  print_bytes(stdout,key,best_keysiz,"key:");
  key[best_keysiz]='\0';
  printf("key is:[%s]\n",key);
 
  free(column);
  free(text);
  free(bin);
  fclose(file);
  return 0;
}
