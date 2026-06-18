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

int base642str(const char* b64,char* str);


#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* _BASE64_H */
