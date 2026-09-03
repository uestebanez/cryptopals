#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <gmp.h>

#include "random.h"

#define PRIME_BITS 512U
#define PRIME_BYTES (PRIME_BITS / 8U)

typedef struct {
    mpz_t n;
    mpz_t exponent;
} rsa_key_t;

static int generate_large_prime(mpz_t prime)
{
    uint8_t bytes[PRIME_BYTES];

    do {
        if (random_bytes(bytes, sizeof(bytes)) != 0) {
            return -1;
        }

        bytes[0] |= 0x80U;
        bytes[sizeof(bytes) - 1U] |= 0x01U;
        mpz_import(prime, sizeof(bytes), 1, 1, 1, 0, bytes);
    } while (mpz_probab_prime_p(prime, 25) == 0);

    return 0;
}

static int is_valid_public_exponent(const mpz_t e, const mpz_t phi)
{
    mpz_t gcd;
    int result;

    mpz_init(gcd);
    mpz_gcd(gcd, e, phi);
    result = mpz_cmp_ui(gcd, 1U) == 0;
    mpz_clear(gcd);

    return result;
}

static void rsa_encrypt(
    mpz_t ciphertext,
    const mpz_t plaintext,
    const rsa_key_t *public_key)
{
    mpz_powm(ciphertext, plaintext, public_key->exponent, public_key->n);
}

static void rsa_decrypt(
    mpz_t plaintext,
    const mpz_t ciphertext,
    const rsa_key_t *private_key)
{
    mpz_powm(plaintext, ciphertext, private_key->exponent, private_key->n);
}

static int test_encrypt_decrypt(
    const rsa_key_t *public_key,
    const rsa_key_t *private_key)
{
    static const char message[] = "Mensaje de prueba RSA";
    uint8_t decrypted_message[sizeof(message) - 1U];
    mpz_t plaintext;
    mpz_t ciphertext;
    mpz_t decrypted_plaintext;
    size_t decrypted_length;
    int result = -1;

    mpz_inits(plaintext, ciphertext, decrypted_plaintext, NULL);
    mpz_import(plaintext, sizeof(message) - 1U, 1, 1, 1, 0, message);
    if (mpz_cmp(plaintext, public_key->n) >= 0) {
        goto cleanup;
    }

    rsa_encrypt(ciphertext, plaintext, public_key);
    rsa_decrypt(decrypted_plaintext, ciphertext, private_key);
    mpz_export(decrypted_message, &decrypted_length, 1, 1, 1, 0,
               decrypted_plaintext);

    if (decrypted_length != sizeof(decrypted_message) ||
        memcmp(decrypted_message, message, sizeof(decrypted_message)) != 0) {
        goto cleanup;
    }

    printf("Prueba de cifrado y descifrado superada: %s\n", message);
    gmp_printf("Texto cifrado (c) = %Zd\n", ciphertext);
    result = 0;

cleanup:
    mpz_clears(plaintext, ciphertext, decrypted_plaintext, NULL);
    return result;
}

int main(void)
{
    mpz_t p;
    mpz_t q;
    mpz_t n;
    mpz_t phi;
    mpz_t e;
    mpz_t d;
    mpz_t p_minus_one;
    mpz_t q_minus_one;
    rsa_key_t public_key;
    rsa_key_t private_key;
    int result = 1;

    mpz_inits(p, q, n, phi, e, d, p_minus_one, q_minus_one, public_key.n,
              public_key.exponent, private_key.n, private_key.exponent, NULL);
    mpz_set_ui(e, 3U);

    for (;;) {
        if (generate_large_prime(p) != 0) {
            goto cleanup;
        }

        do {
            if (generate_large_prime(q) != 0) {
                goto cleanup;
            }
        } while (mpz_cmp(p, q) == 0);

        mpz_mul(n, p, q);
        mpz_sub_ui(p_minus_one, p, 1U);
        mpz_sub_ui(q_minus_one, q, 1U);
        mpz_mul(phi, p_minus_one, q_minus_one);

        if (is_valid_public_exponent(e, phi)) {
            break;
        }

        fprintf(stderr,
                "El exponente publico no es valido; se regeneran p y q.\n");
    }

    if (mpz_invert(d, e, phi) == 0) {
        goto cleanup;
    }

    mpz_set(public_key.n, n);
    mpz_set(public_key.exponent, e);
    mpz_set(private_key.n, n);
    mpz_set(private_key.exponent, d);

    gmp_printf("p = %Zd\n", p);
    gmp_printf("q = %Zd\n", q);
    gmp_printf("n = %Zd\n", n);
    gmp_printf("phi = %Zd\n", phi);
    gmp_printf("Clave publica (n, e) = (%Zd, %Zd)\n", public_key.n,
               public_key.exponent);
    gmp_printf("Clave privada (n, d) = (%Zd, %Zd)\n", private_key.n,
               private_key.exponent);

    if (test_encrypt_decrypt(&public_key, &private_key) != 0) {
        goto cleanup;
    }

    result = 0;

cleanup:
    mpz_clears(p, q, n, phi, e, d, p_minus_one, q_minus_one, public_key.n,
               public_key.exponent, private_key.n, private_key.exponent, NULL);
    return result;
}
