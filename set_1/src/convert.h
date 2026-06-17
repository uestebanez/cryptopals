#ifndef _CONVERT_H
#define _CONVERT_H

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
