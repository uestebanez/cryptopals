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

typedef struct {
    const char *identity;
    mpz_t public_A;
} client_login_request_t;

typedef struct {
    uint8_t salt[SALT_BYTES];
    mpz_t public_B;
} server_login_response_t;

static int generate_private_value(mpz_t private_value)
{
    uint8_t random_bytes_buffer[PRIVATE_VALUE_BYTES];

    if (random_bytes(random_bytes_buffer, sizeof(random_bytes_buffer)) != 0) {
        return -1;
    }

    mpz_import(private_value, sizeof(random_bytes_buffer), 1, 1, 1, 0,
               random_bytes_buffer);
    return 0;
}

static void calculate_password_hash(
    mpz_t x,
    const uint8_t salt[SALT_BYTES],
    const char *password)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX context;

    SHA256_Init(&context);
    SHA256_Update(&context, salt, SALT_BYTES);
    SHA256_Update(&context, password, strlen(password));
    SHA256_Final(digest, &context);

    /* GMP interpreta el digest SHA-256 como un entero sin signo big-endian. */
    mpz_import(x, sizeof(digest), 1, 1, 1, 0, digest);
}

static int calculate_scrambling_parameter(
    mpz_t u,
    const mpz_t public_A,
    const mpz_t public_B)
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

        /* SHA-256 recibe la codificación sin signo big-endian de A y B. */
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
    uint8_t key[SHA256_DIGEST_LENGTH],
    const mpz_t shared_secret)
{
    size_t byte_count;
    size_t written_bytes;
    uint8_t *secret_bytes;

    /* SHA-256 recibe el secreto como entero sin signo big-endian. */
    byte_count = (mpz_sizeinbase(shared_secret, 2) + 7U) / 8U;
    secret_bytes = malloc(byte_count);
    if (secret_bytes == NULL) {
        return -1;
    }
    mpz_export(secret_bytes, &written_bytes, 1, 1, 1, 0, shared_secret);
    if (written_bytes == 0U) {
        secret_bytes[0] = 0U;
        written_bytes = 1U;
    }
    SHA256(secret_bytes, written_bytes, key);
    free(secret_bytes);
    return 0;
}

static int calculate_key_confirmation(
    uint8_t proof[SHA256_DIGEST_LENGTH],
    const uint8_t key[SHA256_DIGEST_LENGTH],
    const uint8_t salt[SALT_BYTES])
{
    unsigned int proof_len;

    if (HMAC(EVP_sha256(), key, SHA256_DIGEST_LENGTH, salt, SALT_BYTES,
             proof, &proof_len) == NULL || proof_len != SHA256_DIGEST_LENGTH) {
        return -1;
    }
    return 0;
}

/**
 * @brief Registra la contraseña de un usuario como un verificador SRP.
 *
 * Genera un salt aleatorio, calcula x = SHA-256(salt || password) y almacena
 * el verificador v = g^x mod N. El valor x solo se utiliza durante el alta;
 * el servidor conserva el salt y el verificador.
 *
 * @param[out] salt Búfer donde se almacena el salt generado.
 * @param[out] verifier Verificador SRP calculado para la contraseña.
 * @param[in] N Módulo primo del grupo SRP.
 * @param[in] g Generador del grupo SRP.
 * @param[in] password Contraseña que se registra.
 * @return 0 si el registro se completa; -1 si no se puede obtener el salt.
 */
static int server_register_user(
    uint8_t salt[SALT_BYTES],
    mpz_t verifier,
    const mpz_t N,
    const mpz_t g,
    const char *password)
{
    mpz_t x;

    mpz_init(x);

    /* El servidor crea y almacena un salt específico para esta contraseña. */
    if (random_bytes(salt, SALT_BYTES) != 0) {
        mpz_clear(x);
        return -1;
    }
    /* x = SHA-256(salt || password). */
    calculate_password_hash(x, salt, password);
    /* El verificador registrado es v = g^x mod N. */
    mpz_powm(verifier, g, x, N);

    mpz_clear(x);
    return 0;
}

static int client_start_login(
    mpz_t private_a,
    mpz_t public_A,
    const mpz_t N,
    const mpz_t g)
{
    /* El cliente interpreta los bytes aleatorios como su secreto efímero a. */
    if (generate_private_value(private_a) != 0) {
        return -1;
    }
    /* A = g^a mod N es el valor público que envía al servidor. */
    mpz_powm(public_A, g, private_a, N);
    return 0;
}

static int server_process_login(
    server_login_response_t *response,
    mpz_t private_b,
    const char *registered_identity,
    const uint8_t registered_salt[SALT_BYTES],
    const mpz_t verifier,
    const mpz_t N,
    const mpz_t g,
    const mpz_t k,
    const client_login_request_t *request)
{
    mpz_t kv;

    if (strcmp(request->identity, registered_identity) != 0 ||
        generate_private_value(private_b) != 0) {
        return -1;
    }

    mpz_init(kv);
    /* B = (k * v + g^b) mod N. */
    mpz_powm(response->public_B, g, private_b, N);
    mpz_mul(kv, k, verifier);
    mpz_add(response->public_B, response->public_B, kv);
    mpz_mod(response->public_B, response->public_B, N);
    /* El cliente necesita el salt para calcular su versión de x. */
    memcpy(response->salt, registered_salt, sizeof(response->salt));
    mpz_clear(kv);
    return 0;
}

static void client_calculate_shared_secret(
    mpz_t shared_secret,
    const mpz_t public_B,
    const mpz_t private_a,
    const mpz_t u,
    const mpz_t x,
    const mpz_t N,
    const mpz_t g,
    const mpz_t k)
{
    mpz_t kgx;
    mpz_t exponent;

    mpz_inits(kgx, exponent, NULL);

    /* Calcula el término k * g^x de la base. */
    mpz_powm(kgx, g, x, N);
    mpz_mul(kgx, kgx, k);
    /* Reduce B - k * g^x módulo N para mantener una base positiva. */
    mpz_sub(kgx, public_B, kgx);
    mpz_mod(kgx, kgx, N);
    /* El exponente del cliente es a + u * x. */
    mpz_mul(exponent, u, x);
    mpz_add(exponent, exponent, private_a);
    /* S_c = (B - k * g^x)^(a + u*x) mod N. */
    mpz_powm(shared_secret, kgx, exponent, N);

    mpz_clears(kgx, exponent, NULL);
}

static void server_calculate_shared_secret(
    mpz_t shared_secret,
    const mpz_t public_A,
    const mpz_t verifier,
    const mpz_t u,
    const mpz_t private_b,
    const mpz_t N)
{
    mpz_t vu;
    mpz_t base;

    mpz_inits(vu, base, NULL);
    /* La base del servidor es A * v^u mod N. */
    mpz_powm(vu, verifier, u, N);
    mpz_mul(base, public_A, vu);
    mpz_mod(base, base, N);
    /* S_s = (A * v^u)^b mod N. */
    mpz_powm(shared_secret, base, private_b, N);

    mpz_clears(vu, base, NULL);
}

/* Challenge 36: Secure Remote Password (SRP). */
int main(void)
{
    mpz_t N;
    mpz_t g;
    mpz_t k;
    mpz_t v;
    mpz_t a;
    mpz_t A;
    mpz_t b;
    mpz_t client_u;
    mpz_t server_u;
    mpz_t client_x;
    mpz_t client_secret;
    mpz_t server_secret;
    uint8_t salt[SALT_BYTES];
    uint8_t client_key[SHA256_DIGEST_LENGTH];
    uint8_t server_key[SHA256_DIGEST_LENGTH];
    uint8_t client_proof[SHA256_DIGEST_LENGTH];
    uint8_t expected_client_proof[SHA256_DIGEST_LENGTH];
    client_login_request_t login_request = {0};
    server_login_response_t login_response = {0};

    mpz_inits(N, g, k, v, a, A, b, client_u, server_u, client_x,
              client_secret, server_secret, NULL);
    mpz_inits(login_request.public_A, login_response.public_B, NULL);

    /* N es el primo grande empleado en el reto 33. */
    mpz_set_str(N, g_large_prime_hex, 16);
    mpz_set_ui(g, 2U);
    mpz_set_ui(k, 3U);

    if (server_register_user(salt, v, N, g, g_password) != 0) {
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, a, A, b, client_u, server_u, client_x,
                   client_secret, server_secret, NULL);
        return 1;
    }
    if (client_start_login(a, A, N, g) != 0) {
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, a, A, b, client_u, server_u, client_x,
                   client_secret, server_secret, NULL);
        return 1;
    }
    /* El cliente envía I y A al servidor a través de la petición simulada. */
    login_request.identity = g_identity;
    mpz_set(login_request.public_A, A);
    /* El servidor responde con el salt registrado y B. */
    if (server_process_login(&login_response, b, g_identity, salt, v, N, g,
                             k, &login_request) != 0) {
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, a, A, b, client_u, server_u, client_x,
                   client_secret, server_secret, NULL);
        return 1;
    }

    /* Ambos extremos calculan u = SHA-256(A || B). */
    if (calculate_scrambling_parameter(client_u, A,
                                       login_response.public_B) != 0 ||
        calculate_scrambling_parameter(server_u, login_request.public_A,
                                       login_response.public_B) != 0) {
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, a, A, b, client_u, server_u, client_x,
                   client_secret, server_secret, NULL);
        return 1;
    }

    /* El cliente reconstruye x = SHA-256(salt || password). */
    calculate_password_hash(client_x, login_response.salt, g_password);
    client_calculate_shared_secret(client_secret, login_response.public_B, a,
                                   client_u, client_x, N, g, k);
    server_calculate_shared_secret(server_secret, login_request.public_A, v,
                                   server_u, b, N);
    if (mpz_cmp(client_secret, server_secret) != 0) {
        fprintf(stderr, "Error: cliente y servidor no comparten el mismo secreto.\n");
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, a, A, b, client_u, server_u, client_x,
                   client_secret, server_secret, NULL);
        return 1;
    }
    /* Ambos extremos derivan K = SHA-256(S). */
    if (derive_session_key(client_key, client_secret) != 0 ||
        derive_session_key(server_key, server_secret) != 0 ||
        memcmp(client_key, server_key, sizeof(client_key)) != 0) {
        fprintf(stderr, "Error: cliente y servidor no derivan la misma clave.\n");
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, a, A, b, client_u, server_u, client_x,
                   client_secret, server_secret, NULL);
        return 1;
    }
    /* El cliente envía HMAC(client_key, salt) y el servidor lo verifica. */
    if (calculate_key_confirmation(client_proof, client_key,
                                   login_response.salt) != 0 ||
        calculate_key_confirmation(expected_client_proof, server_key,
                                   salt) != 0 ||
        CRYPTO_memcmp(client_proof, expected_client_proof,
                      sizeof(client_proof)) != 0) {
        fprintf(stderr, "Error: la prueba HMAC del cliente no es valida.\n");
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, a, A, b, client_u, server_u, client_x,
                   client_secret, server_secret, NULL);
        return 1;
    }

    mpz_clears(login_request.public_A, login_response.public_B, NULL);
    mpz_clears(N, g, k, v, a, A, b, client_u, server_u, client_x,
               client_secret, server_secret, NULL);
    return 0;
}
