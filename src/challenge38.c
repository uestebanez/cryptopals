#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "random.h"

#define SALT_BYTES 16U
#define PRIVATE_VALUE_BYTES 32U

static const char g_large_prime_hex[] =
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
    "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
    "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
    "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
    "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
    "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
    "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
    "fffffffffffff";

static const char g_identity[] = "unai@example.com";
static const char g_password[] = "password";
static const char *const g_password_dictionary[] = {
    "123456",
    "letmein",
    "password",
    "correct horse battery staple",
};

typedef struct {
    const char *identity;
    mpz_t public_A;
} client_login_request_t;

typedef struct {
    uint8_t salt[SALT_BYTES];
    mpz_t public_B;
} server_login_response_t;

typedef struct {
    uint8_t salt[SALT_BYTES];
    uint8_t client_proof[SHA256_DIGEST_LENGTH];
} malicious_server_capture_t;

static int generate_private_value(mpz_t value)
{
    uint8_t bytes[PRIVATE_VALUE_BYTES];

    if (random_bytes(bytes, sizeof(bytes)) != 0) {
        return -1;
    }
    mpz_import(value, sizeof(bytes), 1, 1, 1, 0, bytes);
    return 0;
}

static void calculate_password_hash(
    mpz_t x, const uint8_t salt[SALT_BYTES], const char *password)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX context;

    SHA256_Init(&context);
    SHA256_Update(&context, salt, SALT_BYTES);
    SHA256_Update(&context, password, strlen(password));
    SHA256_Final(digest, &context);
    mpz_import(x, sizeof(digest), 1, 1, 1, 0, digest);
}

static int calculate_scrambling_parameter(
    mpz_t u, const mpz_t public_A, const mpz_t public_B)
{
    const mpz_srcptr public_values[] = {public_A, public_B};
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX context;
    size_t value_index;

    SHA256_Init(&context);
    for (value_index = 0U;
         value_index < sizeof(public_values) / sizeof(public_values[0]);
         ++value_index) {
        size_t byte_count;
        size_t written_bytes;
        uint8_t *bytes;

        byte_count = (mpz_sizeinbase(public_values[value_index], 2) + 7U) / 8U;
        bytes = malloc(byte_count);
        if (bytes == NULL) {
            return -1;
        }
        mpz_export(bytes, &written_bytes, 1, 1, 1, 0,
                   public_values[value_index]);
        if (written_bytes == 0U) {
            bytes[0] = 0U;
            written_bytes = 1U;
        }
        SHA256_Update(&context, bytes, written_bytes);
        free(bytes);
    }
    SHA256_Final(digest, &context);
    mpz_import(u, sizeof(digest), 1, 1, 1, 0, digest);
    return 0;
}

static int derive_session_key(
    uint8_t key[SHA256_DIGEST_LENGTH], const mpz_t shared_secret)
{
    size_t byte_count;
    size_t written_bytes;
    uint8_t *bytes;

    byte_count = (mpz_sizeinbase(shared_secret, 2) + 7U) / 8U;
    bytes = malloc(byte_count);
    if (bytes == NULL) {
        return -1;
    }
    mpz_export(bytes, &written_bytes, 1, 1, 1, 0, shared_secret);
    if (written_bytes == 0U) {
        bytes[0] = 0U;
        written_bytes = 1U;
    }
    SHA256(bytes, written_bytes, key);
    free(bytes);
    return 0;
}

static int calculate_key_confirmation(
    uint8_t proof[SHA256_DIGEST_LENGTH],
    const uint8_t key[SHA256_DIGEST_LENGTH],
    const uint8_t salt[SALT_BYTES])
{
    unsigned int proof_length;

    return HMAC(EVP_sha256(), key, SHA256_DIGEST_LENGTH, salt, SALT_BYTES,
                proof, &proof_length) != NULL &&
                   proof_length == SHA256_DIGEST_LENGTH
               ? 0
               : -1;
}

static void server_calculate_shared_secret(
    mpz_t shared_secret, const mpz_t public_A, const mpz_t verifier,
    const mpz_t u, const mpz_t private_b, const mpz_t N);

/**
 * @brief Captura la prueba de autenticación enviada al servidor malicioso.
 *
 * A diferencia de un servidor legítimo, no compara el HMAC con una prueba
 * esperada. Conserva ambos valores para probar contraseñas candidatas offline
 * y comparar sus HMAC calculados.
 */
static void malicious_server_process_key_confirmation(
    malicious_server_capture_t *capture,
    const uint8_t client_proof[SHA256_DIGEST_LENGTH],
    const uint8_t salt[SALT_BYTES])
{
    memcpy(capture->client_proof, client_proof, sizeof(capture->client_proof));
    memcpy(capture->salt, salt, sizeof(capture->salt));
}

static int malicious_server_start_login(
    server_login_response_t *response, mpz_t private_b, const mpz_t g)
{
    if (random_bytes(response->salt, sizeof(response->salt)) != 0) {
        return -1;
    }

    /* B = g equivale a elegir b = 1, conocido por el atacante. */
    mpz_set_ui(private_b, 1U);
    mpz_set(response->public_B, g);
    return 0;
}

/**
 * @brief Busca en un diccionario la contraseña que produjo el HMAC capturado.
 *
 * Para cada candidata calcula x = SHA-256(salt || password), v = g^x mod N
 * y S = (A * v^u)^b mod N. Si HMAC(SHA-256(S), salt) coincide con la prueba
 * capturada, la candidata es la contraseña del cliente.
 */
static const char *malicious_server_try_dictionary(
    const malicious_server_capture_t *capture, const mpz_t public_A,
    const mpz_t public_B, const mpz_t private_b, const mpz_t N,
    const mpz_t g)
{
    mpz_t u;
    mpz_t x;
    mpz_t verifier;
    mpz_t shared_secret;
    uint8_t key[SHA256_DIGEST_LENGTH];
    uint8_t proof[SHA256_DIGEST_LENGTH];
    size_t candidate_index;
    const char *result = NULL;

    mpz_inits(u, x, verifier, shared_secret, NULL);
    if (calculate_scrambling_parameter(u, public_A, public_B) != 0) {
        goto cleanup;
    }

    for (candidate_index = 0U;
         candidate_index < sizeof(g_password_dictionary) /
                               sizeof(g_password_dictionary[0]);
         ++candidate_index) {
        calculate_password_hash(x, capture->salt,
                                g_password_dictionary[candidate_index]);
        mpz_powm(verifier, g, x, N);
        server_calculate_shared_secret(shared_secret, public_A, verifier, u,
                                       private_b, N);
        if (derive_session_key(key, shared_secret) != 0 ||
            calculate_key_confirmation(proof, key, capture->salt) != 0) {
            goto cleanup;
        }
        if (CRYPTO_memcmp(proof, capture->client_proof, sizeof(proof)) == 0) {
            result = g_password_dictionary[candidate_index];
            break;
        }
    }

cleanup:
    mpz_clears(u, x, verifier, shared_secret, NULL);
    return result;
}

static int client_start_login(
    mpz_t private_a, mpz_t public_A, const mpz_t N, const mpz_t g)
{
    if (generate_private_value(private_a) != 0) {
        return -1;
    }
    mpz_powm(public_A, g, private_a, N);
    return 0;
}

static void client_calculate_shared_secret(
    mpz_t shared_secret, const mpz_t public_B, const mpz_t private_a,
    const mpz_t u, const mpz_t x, const mpz_t N)
{
    mpz_t exponent;

    mpz_init(exponent);
    /* S_c = B^(a + u*x) mod N. */
    mpz_mul(exponent, u, x);
    mpz_add(exponent, exponent, private_a);
    mpz_powm(shared_secret, public_B, exponent, N);
    mpz_clear(exponent);
}

static void server_calculate_shared_secret(
    mpz_t shared_secret, const mpz_t public_A, const mpz_t verifier,
    const mpz_t u, const mpz_t private_b, const mpz_t N)
{
    mpz_t verifier_to_u;
    mpz_t base;

    mpz_inits(verifier_to_u, base, NULL);
    /* S_s = (A * v^u)^b mod N. */
    mpz_powm(verifier_to_u, verifier, u, N);
    mpz_mul(base, public_A, verifier_to_u);
    mpz_mod(base, base, N);
    mpz_powm(shared_secret, base, private_b, N);
    mpz_clears(verifier_to_u, base, NULL);
}

/* Challenge 38: Offline dictionary attack on simplified SRP (skeleton). */
int main(void)
{
    mpz_t N, g, private_a, public_A, private_b, client_u, client_x;
    mpz_t client_secret;
    uint8_t client_key[SHA256_DIGEST_LENGTH];
    uint8_t client_proof[SHA256_DIGEST_LENGTH];
    client_login_request_t request = {0};
    server_login_response_t response = {0};
    malicious_server_capture_t capture = {0};
    const char *recovered_password;
    int status = 1;

    mpz_inits(N, g, private_a, public_A, private_b, client_u, client_x,
              client_secret, request.public_A, response.public_B, NULL);
    mpz_set_str(N, g_large_prime_hex, 16);
    mpz_set_ui(g, 2U);

    if (client_start_login(private_a, public_A, N, g) != 0) {
        goto cleanup;
    }
    request.identity = g_identity;
    mpz_set(request.public_A, public_A);
    if (malicious_server_start_login(&response, private_b, g) != 0) {
        goto cleanup;
    }

    if (calculate_scrambling_parameter(client_u, public_A, response.public_B) !=
        0) {
        goto cleanup;
    }
    calculate_password_hash(client_x, response.salt, g_password);
    client_calculate_shared_secret(client_secret, response.public_B, private_a,
                                   client_u, client_x, N);
    if (derive_session_key(client_key, client_secret) != 0 ||
        calculate_key_confirmation(client_proof, client_key, response.salt) !=
            0) {
        fprintf(stderr, "Error: la autenticacion simplified SRP ha fallado.\n");
        goto cleanup;
    }

    malicious_server_process_key_confirmation(&capture, client_proof,
                                              response.salt);
    recovered_password = malicious_server_try_dictionary(
        &capture, request.public_A, response.public_B, private_b, N, g);
    if (recovered_password == NULL) {
        fprintf(stderr, "Error: no se encontro la contraseña en el diccionario.\n");
        goto cleanup;
    }

    /* El diccionario se prueba sin volver a hablar con el cliente. */
    printf("Contraseña recuperada por diccionario offline: %s\n",
           recovered_password);
    status = 0;

cleanup:
    mpz_clears(N, g, private_a, public_A, private_b, client_u, client_x,
               client_secret, request.public_A, response.public_B, NULL);
    return status;
}
