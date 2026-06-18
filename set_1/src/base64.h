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
 * \brief Convert from an string in base64 to an hexadecimal ascii representation
 * \param b64, buffer with input in base64
 * \param str, output string
 * \return 0 if success
 */
int base642str(const char* b64,char* str);

/**
 * \brief Convert from an string in base64 to binary representation
 * \param b64, buffer with input in base64
 * \param buffer, output buffer 
 * \return 0 if success
 */
int base642bin(const char* b64,uint8_t* buffer);

/**
 * \brief return the size in binary bytes that a base64 string will occupy
 * after decoding it
 */
size_t base64_binsize(const char* b64);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* _BASE64_H */
