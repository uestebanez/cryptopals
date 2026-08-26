#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>

#include "random.h"

static const char g_large_prime_hex[] =
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff";

static int random_private_exponent(mpz_t exponent, const mpz_t prime)
{
    /* candidate representa un desplazamiento antes de moverlo al rango final. */
    mpz_t candidate;
    /* range es el número de exponentes válidos: [2, prime - 2]. */
    mpz_t range;
    /* Los bytes aleatorios se importarán después como un entero GMP. */
    uint8_t *random_buffer;
    /* Cantidad mínima de bits y bytes necesarios para representar range. */
    size_t bit_count;
    size_t byte_count;
    int result = -1;

    /* El intervalo [2, prime - 2] necesita al menos dos valores. */
    if (mpz_cmp_ui(prime, 5U) < 0) {
        return -1;
    }

    /* Inicializa los enteros temporales que gestionará GMP. */
    mpz_inits(candidate, range, NULL);
    /* Hay prime - 3 valores en el intervalo inclusivo [2, prime - 2]. */
    mpz_sub_ui(range, prime, 3U);
    /* Calcula cuántos bits hacen falta para representar esos valores. */
    bit_count = mpz_sizeinbase(range, 2);
    /* Redondea los bits al número entero de bytes que pide random_bytes(). */
    byte_count = (bit_count + 7U) / 8U;
    /* Reserva un búfer temporal de ese tamaño. */
    random_buffer = malloc(byte_count);
    if (random_buffer == NULL) {
        goto cleanup;
    }

    do {
        /* Obtiene bytes aleatorios de la fuente criptográfica del proyecto. */
        if (random_bytes(random_buffer, byte_count) != 0) {
            goto cleanup_buffer;
        }
        /* Borra los bits altos que no caben dentro de bit_count. */
        if (bit_count % 8U != 0U) {
            random_buffer[0] &= (uint8_t)((1U << (bit_count % 8U)) - 1U);
        }
        /* Interpreta los bytes en big-endian y los convierte a mpz_t. */
        mpz_import(candidate, byte_count, 1, 1, 1, 0, random_buffer);
        /* Repite si candidate cae fuera de [0, range - 1] para no sesgarlo. */
    } while (mpz_cmp(candidate, range) >= 0);

    /* Trasladar [0, range - 1] dos posiciones produce [2, prime - 2]. */
    mpz_add_ui(exponent, candidate, 2U);
    result = 0;

cleanup_buffer:
    /* Libera el búfer reservado con malloc(). */
    free(random_buffer);
cleanup:
    /* Libera los enteros temporales inicializados con mpz_inits(). */
    mpz_clears(candidate, range, NULL);
    return result;
}

static int diffie_hellman_exchange(const mpz_t prime, const mpz_t generator)
{
    mpz_t a;
    mpz_t b;
    mpz_t public_a;
    mpz_t public_b;
    mpz_t secret_a;
    mpz_t secret_b;
    int result = -1;

    mpz_inits(a, b, public_a, public_b, secret_a, secret_b, NULL);

    /* Genera el exponente privado aleatorio de Alice. */
    if (random_private_exponent(a, prime) != 0 ||
        /* Genera el exponente privado aleatorio e independiente de Bob. */
        random_private_exponent(b, prime) != 0) {
        goto cleanup;
    }

    /* La clave pública de Alice es A = g^a mod p. */
    mpz_powm(public_a, generator, a, prime);
    /* La clave pública de Bob es B = g^b mod p. */
    mpz_powm(public_b, generator, b, prime);

    /* Alice calcula B^a mod p y Bob calcula A^b mod p. */
    mpz_powm(secret_a, public_b, a, prime);
    mpz_powm(secret_b, public_a, b, prime);

    if (mpz_cmp(secret_a, secret_b) != 0) {
        goto cleanup;
    }
    gmp_printf("Secreto compartido: %Zd\n", secret_a);
    result = 0;

cleanup:
    mpz_clears(a, b, public_a, public_b, secret_a, secret_b, NULL);
    return result;
}

static int test_small_numbers(void)
{
    mpz_t prime;
    mpz_t generator;
    int result;

    mpz_inits(prime, generator, NULL);
    mpz_set_ui(prime, 37U);
    mpz_set_ui(generator, 5U);
    printf("Prueba Diffie-Hellman con numeros pequenos:\n");
    result = diffie_hellman_exchange(prime, generator);
    mpz_clears(prime, generator, NULL);
    return result;
}

static int test_large_numbers(void)
{
    mpz_t prime;
    mpz_t generator;
    int result;

    mpz_inits(prime, generator, NULL);
    if (mpz_set_str(prime, g_large_prime_hex, 16) != 0) {
        mpz_clears(prime, generator, NULL);
        return -1;
    }
    mpz_set_ui(generator, 2U);
    printf("Prueba Diffie-Hellman con el primo grande del reto:\n");
    result = diffie_hellman_exchange(prime, generator);
    mpz_clears(prime, generator, NULL);
    return result;
}

/* Challenge 33: Implement Diffie-Hellman. */
int main(void)
{
    if (test_small_numbers() != 0 || test_large_numbers() != 0) {
        printf("Error en el calculo del secreto compartido.\n");
        return 1;
    }

    return 0;
}
