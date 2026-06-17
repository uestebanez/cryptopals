#ifndef _BASE64_H
#define _BASE64_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \brief Convert from an string to base64
 * \param str, input string
 * \param b64, buffer to store the ouput in base64
 * \return 0 if success
 */
int str2base64(const char* str,char* b64);

/**
 * \brief Auxiliar routine to convert string into raw bytes
 * \param str input string
 * \param bytes, output binary buffer dinamically allocated
 * \return number of bytes in "bytes" buffer or zero
 * \remarks the buffer returned in "bytes" must be freed with "free"
 */
size_t str2bytes(const char* str,uint8_t** bytes);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* _BASE64_H */
