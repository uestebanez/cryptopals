#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

#include "random.h"

#define PRIME_BITS 512U
#define PRIME_BYTES (PRIME_BITS / 8U)
#define ENCRYPTION_COUNT 3U

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

/**
 * @brief Genera un módulo RSA cuyo exponente público sea válido.
 *
 * Los primos y φ(n) solo son necesarios durante la generación. La rutina
 * devuelve el módulo público n = p * q y no expone p ni q al llamador.
 */
static int generate_modulus(mpz_t n, const mpz_t e)
{
    mpz_t p;
    mpz_t q;
    mpz_t phi;
    mpz_t p_minus_one;
    mpz_t q_minus_one;
    int result = -1;

    mpz_inits(p, q, phi, p_minus_one, q_minus_one, NULL);
    for (;;) {
        if (generate_large_prime(p) != 0) {
            goto cleanup;
        }

        do {
            if (generate_large_prime(q) != 0) {
                goto cleanup;
            }
        } while (mpz_cmp(p, q) == 0);

        mpz_sub_ui(p_minus_one, p, 1U);
        mpz_sub_ui(q_minus_one, q, 1U);
        mpz_mul(phi, p_minus_one, q_minus_one);
        if (is_valid_public_exponent(e, phi)) {
            mpz_mul(n, p, q);
            result = 0;
            break;
        }
    }

cleanup:
    mpz_clears(p, q, phi, p_minus_one, q_minus_one, NULL);
    return result;
}

static void rsa_encrypt(
    mpz_t ciphertext,
    const mpz_t plaintext,
    const rsa_key_t *public_key)
{
    mpz_powm(ciphertext, plaintext, public_key->exponent, public_key->n);
}

/**
 * @brief Recupera el mensaje a partir de las claves públicas y c.
 *
 * Esta función representa al atacante: solo recibe los pares públicos (n, e)
 * y los criptogramas.
 */
static void attacker_recover_plaintext(
    mpz_t recovered_plaintext,
    const rsa_key_t public_keys[ENCRYPTION_COUNT],
    const mpz_t ciphertexts[ENCRYPTION_COUNT])
{
    mpz_t N1;
    mpz_t P1;
    mpz_t N2;
    mpz_t P2;
    mpz_t N3;
    mpz_t P3;
    mpz_t N;
    mpz_t X;
    mpz_t term;
    mpz_t r;
    mpz_t r_inverse;

    mpz_inits(N1, P1, N2, P2, N3, P3, N, X, term, r, r_inverse, NULL);
    mpz_mul(N1, public_keys[1].n, public_keys[2].n); // N1 = n2*n3
    mpz_mod(r, N1, public_keys[0].n); // r = N1 mod n1
    // r multiplicado por su inverso modular vale 1 módulo n1.
    if (mpz_invert(r_inverse, r, public_keys[0].n) != 0) {
        /* (N1 * r_inverse) mod n1 es 1. */
        mpz_mul(P1, N1, r_inverse);
    }

    mpz_mul(N2, public_keys[0].n, public_keys[2].n); // N2 = n1*n3
    mpz_mod(r, N2, public_keys[1].n); // r = N2 mod n2
    if (mpz_invert(r_inverse, r, public_keys[1].n) != 0) {
        /* (N2 * r_inverse) mod n2 es 1. */
        mpz_mul(P2, N2, r_inverse);
    }

    mpz_mul(N3, public_keys[0].n, public_keys[1].n); // N3 = n1*n2
    mpz_mod(r, N3, public_keys[2].n); // r = N3 mod n3
    if (mpz_invert(r_inverse, r, public_keys[2].n) != 0) {
        /* (N3 * r_inverse) mod n3 es 1. */
        mpz_mul(P3, N3, r_inverse);
    }

    mpz_mul(X, ciphertexts[0], P1);
    mpz_mul(term, ciphertexts[1], P2);
    mpz_add(X, X, term);
    mpz_mul(term, ciphertexts[2], P3);
    mpz_add(X, X, term);

    mpz_mul(N, public_keys[0].n, public_keys[1].n);
    mpz_mul(N, N, public_keys[2].n);
    mpz_mod(X, X, N);
    if (mpz_root(recovered_plaintext, X, 3U) == 0) {
        fprintf(stderr, "X no tiene una raíz cúbica exacta.\n");
    }

    mpz_clears(N1, P1, N2, P2, N3, P3, N, X, term, r, r_inverse, NULL);
}

int main(void)
{
    static const char message[] = "Mensaje de prueba RSA";
    mpz_t e;
    mpz_t plaintext;
    mpz_t recovered_plaintext;
    uint8_t *recovered_message = NULL;
    size_t recovered_length;
    size_t recovered_capacity;
    rsa_key_t public_keys[ENCRYPTION_COUNT];
    mpz_t ciphertexts[ENCRYPTION_COUNT];
    size_t encryption_index;
    int result = 1;

    mpz_inits(e, plaintext, recovered_plaintext, NULL);
    mpz_set_ui(e, 3U);
    mpz_import(plaintext, sizeof(message) - 1U, 1, 1, 1, 0, message);

    for (encryption_index = 0U; encryption_index < ENCRYPTION_COUNT;
         ++encryption_index) {
        mpz_inits(public_keys[encryption_index].n,
                  public_keys[encryption_index].exponent,
                  ciphertexts[encryption_index], NULL);
    }

    for (encryption_index = 0U; encryption_index < ENCRYPTION_COUNT;
         ++encryption_index) {
        if (generate_modulus(public_keys[encryption_index].n, e) != 0) {
            goto cleanup;
        }
        mpz_set(public_keys[encryption_index].exponent, e);
        if (mpz_cmp(plaintext, public_keys[encryption_index].n) >= 0) {
            goto cleanup;
        }
        rsa_encrypt(ciphertexts[encryption_index], plaintext,
                    &public_keys[encryption_index]);

        gmp_printf("Transmision %zu: n = %Zd, c = %Zd\n",
                   encryption_index + 1U, public_keys[encryption_index].n,
                   ciphertexts[encryption_index]);
    }

    attacker_recover_plaintext(recovered_plaintext, public_keys, ciphertexts);
    recovered_capacity =
        (mpz_sizeinbase(recovered_plaintext, 2) + 7U) / 8U;
    recovered_message = malloc(recovered_capacity + 1U);
    if (recovered_message == NULL) {
        goto cleanup;
    }
    mpz_export(recovered_message, &recovered_length, 1, 1, 1, 0,
               recovered_plaintext);
    recovered_message[recovered_length] = '\0';
    printf("Mensaje recuperado por el atacante: %s\n", recovered_message);

    result = 0;

cleanup:
    free(recovered_message);
    mpz_clears(e, plaintext, recovered_plaintext, NULL);
    for (encryption_index = 0U; encryption_index < ENCRYPTION_COUNT;
         ++encryption_index) {
        mpz_clears(public_keys[encryption_index].n,
                   public_keys[encryption_index].exponent,
                   ciphertexts[encryption_index], NULL);
    }
    return result;
}
