#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <time.h>

#include "msg.h"
#include "sha1.h"

/*
 * A single timing sample is vulnerable to scheduler noise.  A future attacker
 * should repeat each candidate and compare median response times.
 */
#define SERVER_COMPARE_DELAY_NS 10000000L

static const uint8_t g_secret_key[] = "server-secret-key";
static const uint8_t g_message_bytes[] = "foo";
static const message_t g_message = {
    g_message_bytes,
    sizeof(g_message_bytes) - 1U
};

static void server_compare_delay(void)
{
    const struct timespec delay = {
        .tv_sec = 0,
        .tv_nsec = SERVER_COMPARE_DELAY_NS
    };

    nanosleep(&delay, NULL);
}

static uint64_t monotonic_time_ns(void)
{
    struct timespec timestamp;

    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    return ((uint64_t)timestamp.tv_sec * 1000000000U) +
        (uint64_t)timestamp.tv_nsec;
}

static bool server_check(message_t message,
                         const uint8_t signature[SHA1_DIGEST_BYTES])
{
    uint8_t expected_signature[SHA1_DIGEST_BYTES];
    uint32_t i;

    hmac_sha1(expected_signature, g_secret_key, sizeof(g_secret_key) - 1U,
              message.bytes, message.length);
    for (i = 0U; i < SHA1_DIGEST_BYTES; i++) {
        if (expected_signature[i] != signature[i]) {
            return false;
        }
        server_compare_delay();
    }

    return true;
}

static void recover_signature(message_t message,
                              uint8_t signature[SHA1_DIGEST_BYTES])
{
    uint8_t candidate[SHA1_DIGEST_BYTES] = {0};
    uint32_t byte_index;

    for (byte_index = 0U; byte_index < SHA1_DIGEST_BYTES; byte_index++) {
        uint64_t longest_time = 0U;
        uint32_t candidate_byte;

        for (candidate_byte = 0U; candidate_byte <= UINT8_MAX;
             candidate_byte++) {
            uint64_t start_time;
            uint64_t elapsed_time;

            candidate[byte_index] = (uint8_t)candidate_byte;
            start_time = monotonic_time_ns();
            server_check(message, candidate);
            elapsed_time = monotonic_time_ns() - start_time;

            if (elapsed_time > longest_time) {
                longest_time = elapsed_time;
                signature[byte_index] = (uint8_t)candidate_byte;
            }
        }
        candidate[byte_index] = signature[byte_index];
        printf("Byte %u recuperado: %02X\n", byte_index,
               signature[byte_index]);
    }
}

static void print_signature(const char *label,
                            const uint8_t signature[SHA1_DIGEST_BYTES])
{
    uint32_t i;

    printf("%s", label);
    for (i = 0U; i < SHA1_DIGEST_BYTES; i++) {
        printf("%02X", signature[i]);
    }
    printf("\n");
}

int main(void)
{
    uint8_t original_signature[SHA1_DIGEST_BYTES];
    uint8_t recovered_signature[SHA1_DIGEST_BYTES];

    hmac_sha1(original_signature, g_secret_key, sizeof(g_secret_key) - 1U,
              g_message.bytes, g_message.length);
    print_signature("Firma original:  ", original_signature);
    recover_signature(g_message, recovered_signature);
    print_signature("Firma recuperada: ", recovered_signature);

    return server_check(g_message, recovered_signature) ? 0 : 1;
}
