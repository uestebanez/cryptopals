#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include "score.h"
#include "convert.h"

static bool char_is_interesting(char c)
{
    if( isalpha(c) || isblank(c) )
      return true;
    else
      return false;
}

int score_char(char c) 
{
  int score = 0;
  if( char_is_interesting(c) ) {
        char low = tolower(c);
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
  return score;
}

int score_hex_ascii_text(const char* text)
{
  int score = 0;
  int i;
  for( i = 0; text[i] != 0; i+=2 ) {
    char ascii = hexchar2ascii(&text[i]);
    score += score_char(ascii);
  }
  return score;
}

int score_bytes(const uint8_t* buffer,size_t len)
{
  int score = 0;
  size_t i;
  for( i = 0; i < len; i++ ) {
    score += score_char((char)buffer[i]);
  }
  return score;
}
