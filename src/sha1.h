#ifndef SHA1_H
#define SHA1_H

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
 */

#include <stdbool.h>
#include "stdint.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define SHA1_BLOCK_BYTES 64U
#define SHA1_PADDING_MAX_BYTES 72U

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(
    uint32_t state[5],
    const unsigned char buffer[64]
    );

void SHA1Init(
    SHA1_CTX * context
    );

/*
 * Initializes SHA-1 from an existing state and processed byte length.
 * initial_length must be a multiple of SHA1_BLOCK_BYTES.
 */
void SHA1InitV2(
    SHA1_CTX * context,
    const uint32_t state[5],
    uint64_t initial_length);

void SHA1Update(
    SHA1_CTX * context,
    const unsigned char *data,
    uint32_t len
    );

void SHA1Final(
    unsigned char digest[20],
    SHA1_CTX * context
    );

void SHA1(
    char *hash_out,
    const char *str,
    uint32_t len);

/* Calculates SHA1(key || message). */
void sha1_keyed_mac(
    uint8_t mac[20],
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *message,
    uint32_t message_len);

/* Verifies that mac is SHA1(key || message). */
bool sha1_keyed_mac_verify(
    const uint8_t mac[20],
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *message,
    uint32_t message_len);

/* Writes the SHA-1 padding for a message length and returns its byte count. */
uint32_t sha1_padding(
    uint8_t padding[SHA1_PADDING_MAX_BYTES],
    uint64_t message_len);

#if defined(__cplusplus)
}
#endif

#endif /* SHA1_H */
