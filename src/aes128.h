#ifndef _AES128_H
#define _AES128_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define AES128_ECB_MODE 0
#define AES128_CBC_MODE 1

#define AES128_BYTES_IN_BLK 16

/**
 * \brief performs an AES128 encryption in ECB mode
 * \return 0 if success, -1 if error
 */
int aes128_ecb_encrypt(const uint8_t* plain,
                       size_t plain_len,
                       const uint8_t key[16],
                       uint8_t* ciphered,
                       size_t ciphered_size,
                       size_t* ciphered_len);


int aes128_cbc_encrypt(const uint8_t* plain,
                       size_t plain_len,
                       const uint8_t key[16],
                       const uint8_t iv[16],
                       uint8_t* ciphered,
                       size_t ciphered_size,
                       size_t* ciphered_len);

int aes128_check_repeated_blocks(const uint8_t* bytes,
                                 size_t len,
                                 size_t blksiz);

/**
 * \brief detect if a ciphered block is using ECB or CBC
 * \param ciphered cipehered block
 * \param len ciphered block len
 * \return -1 if error
 *         AES128_ECB_MODE if ECB mode
 *         AES128_CBC_MODE if CBC mode
 */
int aes128_detect_ecb_cbc(const uint8_t* ciphered,size_t ciphered_len);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
