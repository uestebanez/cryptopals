#ifndef MSG_H
#define MSG_H

#include <stddef.h>
#include <stdint.h>

#include "aes128.h"

typedef struct {
    const uint8_t *bytes;
    uint32_t length;
} message_t;

/* A CBC ciphertext and the IV required to decrypt it. */
typedef struct {
    uint8_t iv[AES128_BYTES_IN_BLK];
    uint8_t *ciphertext;
    size_t ciphertext_len;
} cbc_encrypted_message_t;

/* Releases ciphertext owned by message and resets its fields. */
void cbc_encrypted_message_clear(cbc_encrypted_message_t *message);

#endif /* MSG_H */
