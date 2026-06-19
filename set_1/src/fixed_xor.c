#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "fixed_xor.h"
#include "base64.h"
#include "convert.h"
#include "score.h"

static void generate_key(unsigned char c, char* key,size_t len)
{
  size_t i;
  char aux[3];
  memset(key,0,len);
  for( i = 0; i < (len-1)/2; i++ ) {
    sprintf(aux,"%02x",c);
    strcat(key,aux);
  }
}

int fixed_xor(const char* input,const char* key, char* output)
{
  if( NULL == input || NULL == key || NULL == output )
    return -1;

  size_t len = strlen(input);
  if( len % 2 != 0 )
    return -2;

  char input_aux[3];
  char key_aux[3];
  uint8_t *input_byte;
  uint8_t *key_byte;
  size_t i;
  for( i = 0; i < len; i+=2 ) {
    input_aux[0] = input[i];
    input_aux[1] = input[i+1];
    input_aux[2] = 0;
    key_aux[0] = key[i];
    key_aux[1] = key[i+1];
    key_aux[2] = 0;

    str2bytes((const char*)input_aux,&input_byte);
    str2bytes((const char*)key_aux,&key_byte);
    uint8_t xor = *input_byte ^ *key_byte;
    sprintf(output,"%02x",xor);
    output+=2;
  }
  return 0;
}

int fixed_xor_bin(const uint8_t* input, const uint8_t* key,size_t keylen,
                  uint8_t* output)
{
  if( NULL == input || NULL == key || NULL == output )
    return -1;

  size_t i;
  for( i = 0; i < keylen; i++ ) {
    output[i] = *input++ ^ *key++;
  }
  return 0;
}

int fixed_xor_try(const char* line,char* best_text,char** bkey)
{
  size_t i;
  char key[strlen(line)+1];
  char output[strlen(line)+1];

  char best_key[strlen(line)+1];
  int score;
  int best_score = -1;

  for( i = 0; i <= 255; i++) {
    generate_key(i,key,sizeof(key));
    memset(output,0,sizeof(output));
    fixed_xor(line,key,output);
    score = score_hex_ascii_text(output);
    if( score > best_score ) {
      best_score = score;
      strcpy(best_text,output);
      strcpy(best_key,key);
    }
  }
  if( NULL != bkey ) {
    *bkey = strdup(best_key);
  }
  return best_score;
}

int fixed_xor_bin_try(uint8_t* buf,size_t size,uint8_t* bkey)
{
  if( NULL == buf || NULL == bkey || 0 == size )
    return -1;

  size_t i;
  uint8_t output[size+1];//allocate one more byte to treat as string
  uint8_t key[size];
  int score;
  int best_score = -1;

  for( i = 0; i <= 255; i++) {
    memset(key,i,sizeof(key));// generate the key
    memset(output,0,sizeof(output));
    fixed_xor_bin(buf,key,size,output);
    output[size]='\0'; // score text requires 
    score = score_bytes(output,size);
    if( score > best_score ) {
      best_score = score;
      *bkey= key[0];
    }
  }
  return best_score;
}

