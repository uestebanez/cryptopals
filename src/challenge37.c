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

static void attacker_start_login(mpz_t public_A)
{
    /* El atacante envía un A inválido para forzar S_s = 0 en el servidor. */
    mpz_set_ui(public_A, 0U);
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
    /* La respuesta expone el salt y B incluso para un A inválido. */
    memcpy(response->salt, registered_salt, sizeof(response->salt));
    mpz_clear(kv);
    return 0;
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

/* Challenge 37: Break SRP with a zero key. */
int main(void)
{
    mpz_t N;
    mpz_t g;
    mpz_t k;
    mpz_t v;
    mpz_t A;
    mpz_t b;
    mpz_t server_u;
    mpz_t attacker_secret;
    mpz_t server_secret;
    uint8_t salt[SALT_BYTES];
    uint8_t attacker_key[SHA256_DIGEST_LENGTH];
    uint8_t server_key[SHA256_DIGEST_LENGTH];
    uint8_t attacker_proof[SHA256_DIGEST_LENGTH];
    uint8_t expected_attacker_proof[SHA256_DIGEST_LENGTH];
    client_login_request_t login_request = {0};
    server_login_response_t login_response = {0};

    mpz_inits(N, g, k, v, A, b, server_u, attacker_secret, server_secret,
              NULL);
    mpz_inits(login_request.public_A, login_response.public_B, NULL);

    /* N es el primo grande empleado en el reto 33. */
    mpz_set_str(N, g_large_prime_hex, 16);
    mpz_set_ui(g, 2U);
    mpz_set_ui(k, 3U);

    printf("[1/5] El servidor registra al usuario objetivo.\n");
    if (server_register_user(salt, v, N, g, g_password) != 0) {
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, A, b, server_u, attacker_secret,
                   server_secret, NULL);
        return 1;
    }
    attacker_start_login(A);
    /* El atacante suplanta la identidad registrada y envía A = 0. */
    printf("[2/5] El atacante suplanta la identidad y envia A = 0.\n");
    login_request.identity = g_identity;
    mpz_set(login_request.public_A, A);
    /* El servidor responde con el salt registrado y B. */
    if (server_process_login(&login_response, b, g_identity, salt, v, N, g,
                             k, &login_request) != 0) {
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, A, b, server_u, attacker_secret,
                   server_secret, NULL);
        return 1;
    }

    /* El servidor calcula u = SHA-256(A || B) antes de obtener S_s. */
    printf("[3/5] El servidor responde con salt y B, sin rechazar A = 0.\n");
    if (calculate_scrambling_parameter(server_u, login_request.public_A,
                                       login_response.public_B) != 0) {
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, A, b, server_u, attacker_secret,
                   server_secret, NULL);
        return 1;
    }

    server_calculate_shared_secret(server_secret, login_request.public_A, v,
                                   server_u, b, N);
    /* A = 0 hace que S_s = (0 * v^u)^b mod N = 0. */
    mpz_set_ui(attacker_secret, 0U);
    if (mpz_cmp(attacker_secret, server_secret) != 0) {
        fprintf(stderr, "Error: el servidor no calculo el secreto predecible.\n");
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, A, b, server_u, attacker_secret,
                   server_secret, NULL);
        return 1;
    }
    printf("[4/5] El atacante predice correctamente S = 0 y deriva K.\n");
    /* El atacante conoce S = 0 y por tanto puede calcular K = SHA-256(S). */
    if (derive_session_key(attacker_key, attacker_secret) != 0 ||
        derive_session_key(server_key, server_secret) != 0 ||
        memcmp(attacker_key, server_key, sizeof(attacker_key)) != 0) {
        fprintf(stderr, "Error: el atacante no pudo derivar la clave del servidor.\n");
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, A, b, server_u, attacker_secret,
                   server_secret, NULL);
        return 1;
    }
    /* Con el salt recibido, el atacante envía un HMAC que el servidor acepta. */
    printf("[5/5] El atacante envia HMAC(K, salt) al servidor.\n");
    if (calculate_key_confirmation(attacker_proof, attacker_key,
                                   login_response.salt) != 0 ||
        calculate_key_confirmation(expected_attacker_proof, server_key,
                                   salt) != 0 ||
        CRYPTO_memcmp(attacker_proof, expected_attacker_proof,
                      sizeof(attacker_proof)) != 0) {
        fprintf(stderr, "Error: el servidor rechazo el HMAC del atacante.\n");
        mpz_clears(login_request.public_A, login_response.public_B, NULL);
        mpz_clears(N, g, k, v, A, b, server_u, attacker_secret,
                   server_secret, NULL);
        return 1;
    }
    printf("Ataque exitoso: el servidor ha autenticado al atacante.\n");

    mpz_clears(login_request.public_A, login_response.public_B, NULL);
    mpz_clears(N, g, k, v, A, b, server_u, attacker_secret, server_secret,
               NULL);
    return 0;
}
