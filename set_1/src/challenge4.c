#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include "base64.h"
#include "fixed_xor.h"

#define LINE_SIZE 60

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

static int try_fixed_xor(const char* line,char* best_text)
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
    score = score_text(output);
    if( score > best_score ) {
      best_score = score;
      strcpy(best_text,output);
      strcpy(best_key,key);
    }
  }
  return best_score;
}


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
    score = try_fixed_xor(line,deciphered);
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
