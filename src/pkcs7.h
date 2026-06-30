#ifndef _PKCS7_H
#define _PKCS7_H

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \brief return the number of bytes needed for the padding
 * \param bytesno number of bytes with information to pad
 * \param blklen ciphering block length
 * \return number of padding bytes
 */
static inline size_t pkcs7_needed_pad(size_t bytesno,size_t blklen)
{
  return blklen - (bytesno % blklen);
}

/**
 * \brief Add pad to the end of the buffer if needed.
 * \param buffer input binary buffer
 * \param bufsiz capacity of the binary buffer 
 * \param bytesno number of bytes in the buffer
 * \param blklen block length for the ciphering operation
 * \return number of padding bytes or -1 if error
 * \remarks buffer MUST have size enough for the padding if needed. That is
 * it must have a size multiple of the blklen.
 */
int pkcs7_pad(uint8_t* buffer,size_t bufsiz,size_t bytesno,size_t blklen);

/**
 * \brief unpad a buffer
 * \param buffer input buffer
 * \param len length of the buffer
 * \param blklen block length
 * \upadded_len output parameter to store the final lenght of the unpadded buffer
 * \return 0 if sucess, -1 if error
 */
int pkcs7_unpad(uint8_t* buffer,size_t len,size_t blklen,size_t* unpadded_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif
