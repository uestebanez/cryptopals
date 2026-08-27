#include <stdint.h>
#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes128.h"
#include "msg.h"
#include "pkcs7.h"
#include "random.h"
#include "sha1.h"

#define SYMMETRIC_KEY_BYTES 16U

static const uint8_t g_alice_message[] =
    "Bob, this message is protected with AES-CBC.";
static const uint8_t g_bob_message[] =
    "Alice, I received your protected message.";

static int encrypt_message(
    cbc_encrypted_message_t *encrypted_message,
    const uint8_t *message,
    size_t message_len,
    const uint8_t key[SYMMETRIC_KEY_BYTES])
{
    uint8_t *padded_message;
    size_t padding_len;
    size_t padded_len;
    size_t ciphertext_len;
    int result = -1;

    encrypted_message->ciphertext = NULL;
    encrypted_message->ciphertext_len = 0U;

    /* AES-CBC requires a full number of blocks, so add PKCS#7 padding. */
    padding_len = pkcs7_needed_pad(message_len, AES128_BYTES_IN_BLK);
    padded_len = message_len + padding_len;
    padded_message = malloc(padded_len);
    if (padded_message == NULL) {
        return -1;
    }
    memcpy(padded_message, message, message_len);
    if (pkcs7_pad(padded_message, padded_len, message_len,
                  AES128_BYTES_IN_BLK) < 0) {
        goto cleanup_padded_message;
    }

    encrypted_message->ciphertext = malloc(padded_len);
    if (encrypted_message->ciphertext == NULL) {
        goto cleanup_padded_message;
    }
    if (random_bytes(encrypted_message->iv, sizeof(encrypted_message->iv)) != 0) {
        goto cleanup_channel_message;
    }
    if (aes128_cbc_encrypt(padded_message, padded_len, key,
                           encrypted_message->iv, encrypted_message->ciphertext,
                           padded_len, &ciphertext_len) != 0) {
        goto cleanup_channel_message;
    }

    encrypted_message->ciphertext_len = ciphertext_len;
    result = 0;

cleanup_channel_message:
    if (result != 0) {
        cbc_encrypted_message_clear(encrypted_message);
    }
cleanup_padded_message:
    free(padded_message);
    return result;
}

static int decrypt_message(
    uint8_t **plaintext,
    size_t *plaintext_len,
    const cbc_encrypted_message_t *encrypted_message,
    const uint8_t key[SYMMETRIC_KEY_BYTES])
{
    uint8_t *padded_plaintext;
    size_t padded_plaintext_len;

    if (encrypted_message->ciphertext == NULL ||
        encrypted_message->ciphertext_len == 0U) {
        return -1;
    }

    padded_plaintext = malloc(encrypted_message->ciphertext_len);
    if (padded_plaintext == NULL) {
        return -1;
    }
    if (aes128_cbc_decrypt(encrypted_message->ciphertext,
                           encrypted_message->ciphertext_len, key,
                           encrypted_message->iv, padded_plaintext,
                           encrypted_message->ciphertext_len,
                           &padded_plaintext_len) != 0 ||
        pkcs7_unpad(padded_plaintext, padded_plaintext_len,
                    AES128_BYTES_IN_BLK, plaintext_len) != 0) {
        free(padded_plaintext);
        return -1;
    }

    *plaintext = padded_plaintext;
    return 0;
}

static void print_text_message(const char *label,
                               const uint8_t *message,
                               size_t message_len)
{
    fputs(label, stdout);
    fwrite(message, 1U, message_len, stdout);
    fputc('\n', stdout);
}

static int derive_symmetric_key(
    uint8_t key[SYMMETRIC_KEY_BYTES],
    const mpz_t shared_secret)
{
    uint8_t digest[SHA1_DIGEST_BYTES];
    uint8_t *secret_bytes;
    size_t byte_count;
    size_t written_bytes = 0U;

    /* Reserve enough space for the unsigned big-endian representation. */
    byte_count = (mpz_sizeinbase(shared_secret, 2) + 7U) / 8U;
    secret_bytes = malloc(byte_count);
    if (secret_bytes == NULL) {
        return -1;
    }

    /* mpz_export emits no byte for zero, so encode zero explicitly as 0x00. */
    if (mpz_sgn(shared_secret) == 0) {
        secret_bytes[0] = 0U;
        written_bytes = 1U;
    } else {
        mpz_export(secret_bytes, &written_bytes, 1, 1, 1, 0, shared_secret);
    }

    SHA1((char *)digest, (const char *)secret_bytes,
         (uint32_t)written_bytes);
    memcpy(key, digest, SYMMETRIC_KEY_BYTES);
    free(secret_bytes);
    return 0;
}

static void bob_receive_parameters(
    mpz_t public_b,
    mpz_t shared_secret_b,
    const mpz_t received_a,
    const mpz_t received_prime,
    const mpz_t received_generator,
    const mpz_t private_b)
{
    /* Bob constructs B = g^b mod p using the received group parameters. */
    mpz_powm(public_b, received_generator, private_b, received_prime);
    /* Bob derives the secret S = A^b mod p. */
    mpz_powm(shared_secret_b, received_a, private_b, received_prime);
}

static void alice_receive_public_b(
    mpz_t shared_secret_a,
    const mpz_t received_b,
    const mpz_t received_prime,
    const mpz_t private_a)
{
    /* Alice derives the secret S = B^a mod p. */
    mpz_powm(shared_secret_a, received_b, private_a, received_prime);
}

/* Challenge 34: Diffie-Hellman MITM key-fixing attack. */
int main(void)
{
    mpz_t prime;
    mpz_t generator;
    mpz_t a;
    mpz_t b;
    mpz_t public_a;
    mpz_t public_b;
    mpz_t shared_secret_a;
    mpz_t shared_secret_b;
    mpz_t forwarded_a;
    mpz_t forwarded_b;
    mpz_t mallory_secret;
    uint8_t symmetric_key_a[SYMMETRIC_KEY_BYTES];
    uint8_t symmetric_key_b[SYMMETRIC_KEY_BYTES];
    uint8_t symmetric_key_mallory[SYMMETRIC_KEY_BYTES];
    cbc_encrypted_message_t alice_message = {0};
    cbc_encrypted_message_t bob_message = {0};
    uint8_t *bob_plaintext = NULL;
    size_t bob_plaintext_len;
    uint8_t *mallory_alice_plaintext = NULL;
    size_t mallory_alice_plaintext_len;
    uint8_t *alice_plaintext = NULL;
    size_t alice_plaintext_len;
    uint8_t *mallory_bob_plaintext = NULL;
    size_t mallory_bob_plaintext_len;
    int result = 1;

    mpz_inits(prime, generator, a, b, public_a, public_b, shared_secret_a,
              shared_secret_b, forwarded_a, forwarded_b, mallory_secret, NULL);

    /* Public Diffie-Hellman parameters. */
    mpz_set_ui(prime, 37U);
    mpz_set_ui(generator, 5U);

    /* Private exponents of Alice and Bob for this small test. */
    mpz_set_ui(a, 15U);
    mpz_set_ui(b, 13U);

    /* Public key A sent by Alice: A = g^a mod p. */
    mpz_powm(public_a, generator, a, prime);

    /* Mallory intercepts A and forwards p to Bob instead. */
    mpz_set(forwarded_a, prime);
    /* Bob receives the altered public key together with p and g. */
    bob_receive_parameters(public_b, shared_secret_b, forwarded_a, prime,
                           generator, b);

    /* Mallory intercepts B and forwards p to Alice instead. */
    mpz_set(forwarded_b, prime);
    /* Alice derives her secret from the altered public key. */
    alice_receive_public_b(shared_secret_a, forwarded_b, prime, a);

    /* p^a mod p and p^b mod p are zero, so Mallory knows the secret. */
    mpz_set_ui(mallory_secret, 0U);
    if (mpz_cmp(shared_secret_a, shared_secret_b) != 0) {
        goto cleanup;
    }

    if (derive_symmetric_key(symmetric_key_a, shared_secret_a) != 0 ||
        derive_symmetric_key(symmetric_key_b, shared_secret_b) != 0 ||
        derive_symmetric_key(symmetric_key_mallory, mallory_secret) != 0 ) {
        goto cleanup;
    }

    encrypt_message(&alice_message, g_alice_message,
                    sizeof(g_alice_message) - 1U, symmetric_key_a);
    decrypt_message(&bob_plaintext, &bob_plaintext_len,
                    &alice_message, symmetric_key_b);
    decrypt_message(&mallory_alice_plaintext, &mallory_alice_plaintext_len,
                    &alice_message, symmetric_key_mallory);
    print_text_message("Alice envia: ", g_alice_message,
                       sizeof(g_alice_message) - 1U);
    print_text_message("Bob descifra: ", bob_plaintext, bob_plaintext_len);
    print_text_message("Mallory descifra: ", mallory_alice_plaintext,
                       mallory_alice_plaintext_len);

    encrypt_message(&bob_message, g_bob_message,
                    sizeof(g_bob_message) - 1U, symmetric_key_b);
    decrypt_message(&alice_plaintext, &alice_plaintext_len,
                    &bob_message, symmetric_key_a);
    decrypt_message(&mallory_bob_plaintext, &mallory_bob_plaintext_len,
                    &bob_message, symmetric_key_mallory);
    print_text_message("Bob envia: ", g_bob_message,
                       sizeof(g_bob_message) - 1U);
    print_text_message("Alice descifra: ", alice_plaintext,
                       alice_plaintext_len);
    print_text_message("Mallory descifra: ", mallory_bob_plaintext,
                       mallory_bob_plaintext_len);
    result = 0;

cleanup:
    free(bob_plaintext);
    free(mallory_alice_plaintext);
    free(alice_plaintext);
    free(mallory_bob_plaintext);
    cbc_encrypted_message_clear(&alice_message);
    cbc_encrypted_message_clear(&bob_message);
    mpz_clears(prime, generator, a, b, public_a, public_b, shared_secret_a,
               shared_secret_b, forwarded_a, forwarded_b, mallory_secret,
               NULL);
    return result;
}
