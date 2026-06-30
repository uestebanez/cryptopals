#ifndef _SCORE_H
#define _SCORE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int score_hex_ascii_text(const char* text);
int score_bytes(const uint8_t* buffer,size_t len);
int score_char(char c);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
