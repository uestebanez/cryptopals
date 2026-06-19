#ifndef _CONVERT_H
#define _CONVERT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \brief convert from ascii string to hexadecima ascii representation.
 * Two bytes per ascii char
 * \param ascii string with the text (standard C string)
 * \param hex_ascii output with the conversion to hexadecimal ascii. (also standard C string but with two digits per byte).
 * \return number of chars processed from input string or zero
 * \remarks hex_ascii must have doble of the ascii parameter size and an additiona byte to store the \0.
 */
int ascii2hex_ascii(const char* ascii, char* hex_ascii);

/**
 * \brief Auxiliar routine to convert string into raw bytes
 * \param str input string in ascii hex
 * \param bytes, output binary buffer dinamically allocated
 * \return number of bytes in "bytes" buffer or zero
 * \remarks the buffer returned in "bytes" must be freed with "free"
 */
size_t str2bytes(const char* str,uint8_t** bytes);

/**
 * \brief convert a binary buffer to ascii hex string
 * \param buf binary buffer
 * \param len length of the binary buffer
 * \param output buffer to store the ascii hex (must have space enough)
 * \return number of bytes converted
 */
size_t bytes2hex_ascii(const uint8_t* buf,size_t len,char* output);

/**
 * \brief convert hexadecimal ascii char to single binary ascii char
 * \param hex hexadecimal ascci. two chars. e.g: "A0" End of string is not needed
 * \return the character
 * \remarks This function does not take care if the output is a printable 
 * character or not. This function does not look for zero end in the string,just
 * get two chars from de string and convert them
 */
char hexchar2ascii(const char* hex);


/**
 * \brief convert a single hexadecimal char to single binary ascii char. 
 * \param hex hexadecimal ascci. two zero-ended chars. e.g: "A0"
 * \return the character
 * \remarks This function does not take care if the output is a printable 
 * character or not
 */
char hex2bin(const char* hex);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
