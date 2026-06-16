#ifndef _BASE64_H
#define _BASE64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Convert from an string to base64
 * @param str, input string
 * @param b64, output with the base64
 * @return same pointer as b64
 */
char* str2base64(const char* str,char* b64);

/*
 * Auxiliar routine to convert string into raw bytes
 * @remarks the buffer returned must be freed with "free"
 */
uint8_t* str2bytes(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* _BASE64_H */
