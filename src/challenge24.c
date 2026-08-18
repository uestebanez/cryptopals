#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mt19937.h"
#include "print.h"
#include "random.h"

#define KNOWN_SUFFIX "AAAAAAAAAAAAAA"
#define TOKEN_LENGTH 16
#define TIMESTAMP_SEARCH_WINDOW 256

static const uint8_t known_suffix[] = KNOWN_SUFFIX;

static const uint8_t plaintext[] =
  "El cifrado de flujo usa la misma operacion para cifrar y descifrar."
  KNOWN_SUFFIX;

_Static_assert(sizeof(known_suffix) - 1 == 14,
               "El sufijo conocido debe tener 14 bytes");

static void mt19937_xor(const uint8_t *input, size_t input_len,
                        uint16_t seed, mt19937_t *rng, uint8_t *output)
{
  size_t input_index = 0;

  mt19937_seed(rng, seed);

  while (input_index < input_len) {
    uint32_t keystream_word = mt19937_extract(rng);

    for (size_t byte_index = 0;
         byte_index < sizeof(keystream_word) && input_index < input_len;
         byte_index++, input_index++) {
      uint8_t keystream_byte =
        (uint8_t)(keystream_word >> (byte_index * CHAR_BIT));

      output[input_index] = input[input_index] ^ keystream_byte;
    }
  }
}

static void mt19937_generate_bytes(uint32_t seed, mt19937_t *rng,
                                   uint8_t *output, size_t output_len)
{
  size_t output_index = 0;

  mt19937_seed(rng, seed);

  while (output_index < output_len) {
    uint32_t random_word = mt19937_extract(rng);

    for (size_t byte_index = 0;
         byte_index < sizeof(random_word) && output_index < output_len;
         byte_index++, output_index++) {
      output[output_index] =
        (uint8_t)(random_word >> (byte_index * CHAR_BIT));
    }
  }
}

static int recover_seed(const uint8_t *ciphertext, size_t ciphertext_len,
                        const uint8_t *suffix, size_t suffix_len,
                        uint16_t *recovered_seed)
{
  mt19937_t rng;
  uint8_t *decrypted;

  if (ciphertext == NULL || suffix == NULL || recovered_seed == NULL ||
      suffix_len > ciphertext_len) {
    return -1;
  }

  decrypted = malloc(ciphertext_len);
  if (decrypted == NULL) {
    return -1;
  }

  for (uint32_t candidate = 0; candidate <= UINT16_MAX; candidate++) {
    mt19937_xor(ciphertext, ciphertext_len, (uint16_t)candidate, &rng,
                decrypted);

    if (memcmp(decrypted + ciphertext_len - suffix_len, suffix,
               suffix_len) == 0) {
      *recovered_seed = (uint16_t)candidate;
      free(decrypted);
      return 0;
    }
  }

  free(decrypted);
  return -1;
}

static int recover_timestamp_seed(const uint8_t *token, size_t token_len,
                                  uint32_t current_timestamp,
                                  uint32_t *recovered_seed)
{
  mt19937_t rng;
  uint8_t candidate_token[TOKEN_LENGTH];

  if (token == NULL || recovered_seed == NULL ||
      token_len != sizeof(candidate_token)) {
    return -1;
  }

  for (uint32_t seconds_ago = 0;
       seconds_ago <= TIMESTAMP_SEARCH_WINDOW;
       seconds_ago++) {
    uint32_t candidate_seed = current_timestamp - seconds_ago;

    mt19937_generate_bytes(candidate_seed, &rng, candidate_token,
                           sizeof(candidate_token));

    if (memcmp(token, candidate_token, token_len) == 0) {
      *recovered_seed = candidate_seed;
      return 0;
    }
  }

  return -1;
}

/*
 * Challenge 24: Create the MT19937 stream cipher and break it.
 *
 * Pendiente:
 * - Recuperar una semilla de 16 bits conocida una parte del texto plano.
 * - Generar y validar tokens de restablecimiento basados en MT19937.
 */

static int challenge24_recover_16_bit_seed(void)
{
  mt19937_t rng;
  uint16_t seed;
  uint16_t recovered_seed;
  size_t plaintext_len = sizeof(plaintext) - 1;
  uint8_t ciphertext[sizeof(plaintext) - 1];
  uint8_t decrypted[sizeof(plaintext)];

  printf("=== Reto 24.1: recuperar una semilla de 16 bits ===\n");

  if (random_bytes((uint8_t *)&seed, sizeof(seed)) != 0) {
    fprintf(stderr, "No se pudo generar la semilla.\n");
    return 1;
  }

  mt19937_xor(plaintext, plaintext_len, seed, &rng, ciphertext);

  if (recover_seed(ciphertext, plaintext_len, known_suffix,
                   sizeof(known_suffix) - 1, &recovered_seed) != 0) {
    fprintf(stderr, "No se pudo recuperar la semilla.\n");
    return 1;
  }

  mt19937_xor(ciphertext, plaintext_len, recovered_seed, &rng, decrypted);
  decrypted[plaintext_len] = '\0';

  printf("Semilla de 16 bits: %u\n", seed);
  printf("Mensaje a cifrar (%zu bytes): %s\n", plaintext_len,
         (const char *)plaintext);
  printf("Mensaje cifrado (%zu bytes):\n", plaintext_len);
  print_bytes(stdout, ciphertext, plaintext_len, NULL);
  printf("Semilla recuperada: %u\n", recovered_seed);
  printf("Mensaje descifrado: %s\n", (const char *)decrypted);

  if (recovered_seed != seed) {
    fprintf(stderr, "La semilla recuperada no coincide con la original.\n");
    return 1;
  }

  if (memcmp(plaintext, decrypted, plaintext_len) != 0) {
    fprintf(stderr, "El mensaje descifrado no coincide con el original.\n");
    return 1;
  }

  printf("El mensaje descifrado coincide con el original.\n");
  return 0;
}

static int challenge24_timestamp_token(void)
{
  mt19937_t rng;
  time_t now;
  uint32_t seed;
  uint32_t recovered_seed;
  uint32_t random_value;
  uint32_t simulated_wait;
  uint32_t recovery_timestamp;
  uint8_t token[TOKEN_LENGTH];

  printf("\n=== Reto 24.2: token con semilla de timestamp ===\n");

  now = time(NULL);
  if (now == (time_t)-1) {
    fprintf(stderr, "No se pudo obtener el timestamp actual.\n");
    return 1;
  }

  seed = (uint32_t)now;
  mt19937_generate_bytes(seed, &rng, token, sizeof(token));

  if (random_bytes((uint8_t *)&random_value, sizeof(random_value)) != 0) {
    fprintf(stderr, "No se pudo simular la espera antes del ataque.\n");
    return 1;
  }

  simulated_wait = 1 + (random_value % TIMESTAMP_SEARCH_WINDOW);
  recovery_timestamp = seed + simulated_wait;

  if (recover_timestamp_seed(token, sizeof(token), recovery_timestamp,
                             &recovered_seed) != 0) {
    fprintf(stderr, "No se pudo recuperar la semilla del token.\n");
    return 1;
  }

  printf("Timestamp usado como semilla: %u\n", seed);
  print_bytes(stdout, token, sizeof(token), "Token: ");
  printf("Espera simulada antes del ataque: %u segundos\n", simulated_wait);
  printf("Timestamp desde el que se inicia la búsqueda: %u\n",
         recovery_timestamp);
  printf("Timestamp recuperado: %u\n", recovered_seed);

  if (recovered_seed != seed) {
    fprintf(stderr, "El timestamp recuperado no coincide con el original.\n");
    return 1;
  }

  printf("El timestamp recuperado coincide con el original.\n");
  return 0;
}

int main(void)
{
  if (challenge24_recover_16_bit_seed() != 0) {
    return 1;
  }

  return challenge24_timestamp_token();
}
