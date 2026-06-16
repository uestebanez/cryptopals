#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include "base64.h"
#include "fixed_xor.h"

#define CIPHERED (const char*)"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"

static char hex2bin(const char* hex)
{
  int ascii;
  sscanf(hex,"%x",&ascii);
  return ascii;
}

static char hexchar2ascii(const char* hex)
{
  char aux[3];
  aux[0] = hex[0];
  aux[1] = hex[1];
  aux[2] = 0;
  return hex2bin(aux);
}

static void print_hex_as_ascii(const char* hex)
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

static bool char_is_interesting(char c)
{
    if( isalpha(c) || isblank(c) )
      return true;
    else
      return false;
}

static int score_text(const char* text)
{
  int score = 0;
  int i;
  for( i = 0; text[i] != 0; i+=2 ) {
    char ascii = hexchar2ascii(&text[i]);
    if( char_is_interesting(ascii) ) {
        char low = tolower(ascii);
        switch(low) {
          case ' ':
            score += 14; // me lo he inventado
            break;
          case 't':
            score += 16;
            break;
          case 'e':
            score += 12;
          break;
          case 'a':
            score += 8;
          break;
          case 'i':
          case 'o':
            score += 7;
          break;
          case 'r':
          case 'n':
          case 's':
          case 'h':
            score += 6;
            break;
          break;
          case 'd':
          case 'l':
            score += 4;
          break;
          case 'u':
          case 'w':
          case 'y':
          case 'c':
          case 'f':
          case 'g':
          case 'm':
            score += 2;
          break;
          case 'b':
          case 'p':
            score += 1;
            break;
        }
    }
  }
  return score;
}

int main(int argc,char** argv)
{
  size_t i;
  char key[strlen(CIPHERED)+1];
  char output[strlen(CIPHERED)+1];

  char best_key[strlen(CIPHERED)+1];
  char best_text[strlen(CIPHERED)+1];
  int score;
  int best_score = -1;


  for( i = 0; i <= 255; i++) {
    generate_key(i,key,sizeof(key));
    memset(output,0,sizeof(output));
    fixed_xor(CIPHERED,key,output);
    score = score_text(output);
    if( score > best_score ) {
      best_score = score;
      strcpy(best_text,output);
      strcpy(best_key,key);
    }
    if( score > 0 ) {
      printf("iteration %ld -> output=[",i);
      print_hex_as_ascii(output);
      printf("] score=%d\n",score);
    }
  }
  printf("text=[");
  print_hex_as_ascii(best_text);
  printf("] score:%d\n",best_score);
  return 0;
}
