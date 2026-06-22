#ifndef _AES128_H
#define _AES128_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int aes128_ecb_encrypt(const uint8_t* plain,
                       size_t plain_len,
                       const uint8_t key[16],
                       uint8_t* ciphered,
                       size_t ciphered_size,
                       size_t* ciphered_len);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
