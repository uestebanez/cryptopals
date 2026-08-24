#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "print.h"
#include "sha1.h"

static const uint8_t g_key[] = "YELLOW SUBMARINE";
static uint8_t g_message[] = "The quick brown fox jumps over the lazy dog";

typedef struct {
    const uint8_t *bytes;
    uint32_t length;
} message_t;

static bool server_verify(message_t message, const uint8_t mac[20])
{
    return sha1_keyed_mac_verify(mac, g_key, sizeof(g_key) - 1U,
                                 message.bytes, message.length);
}

static void sha1_mac_to_state(const uint8_t mac[20], uint32_t state[5])
{
    uint32_t i;

    for (i = 0U; i < 5U; i++) {
        state[i] = ((uint32_t)mac[i * 4U] << 24U) |
                   ((uint32_t)mac[i * 4U + 1U] << 16U) |
                   ((uint32_t)mac[i * 4U + 2U] << 8U) |
                   (uint32_t)mac[i * 4U + 3U];
    }
}

/*
 * Challenge 29: Break a SHA-1 keyed MAC using length extension.
 *
 * Pendiente:
 * - Obtener un MAC válido para un mensaje original.
 * - Construir el padding SHA-1 para una longitud de clave desconocida.
 * - Extender el mensaje y forjar su MAC.
 */
int main(void)
{
    SHA1_CTX extended_context;
    uint8_t mac[20];
    uint8_t padding[SHA1_PADDING_MAX_BYTES];
    uint32_t state[5];
    uint32_t padding_len;
    const uint8_t payload[] = ";admin=true";
    uint8_t hacked_msg[(sizeof(g_message) - 1U) + SHA1_PADDING_MAX_BYTES +
                       (sizeof(payload) - 1U)];
    message_t original_message = {
        g_message,
        sizeof(g_message) - 1U
    };
    message_t forged_message;
    uint64_t original_length = (sizeof(g_key) - 1U) + original_message.length;


    printf("=== Reto 29: SHA-1 length extension attack ===\n");


    printf("Mensaje de prueba: %s \n", g_message);

    sha1_keyed_mac(mac, g_key, sizeof(g_key) - 1U,
                   original_message.bytes, original_message.length);
    print_bytes(stdout,mac,20,"MAC:[","]");
    if (server_verify(original_message, mac)) {
      printf("MAC is right\n");
    } else {
      printf("Wrong MAC!!!\n");
    }
    sha1_mac_to_state(mac, state);
    padding_len = sha1_padding(padding, original_length);
    printf("Padding len=%"PRIu32"\n",padding_len);

    uint8_t *hacked_ptr = hacked_msg;
    memcpy(hacked_ptr, original_message.bytes, original_message.length);
    hacked_ptr += original_message.length;
    memcpy(hacked_ptr, padding, padding_len);
    hacked_ptr += padding_len;
    memcpy(hacked_ptr, payload, sizeof(payload) - 1U);
    hacked_ptr += sizeof(payload) - 1U;
    forged_message.bytes = hacked_msg;
    forged_message.length = (uint32_t)(hacked_ptr - hacked_msg);

    uint64_t processed_len = padding_len+sizeof(g_message)-1+sizeof(g_key)-1;
    printf("Processed len=%"PRIu64"\n",processed_len);

    SHA1InitV2(&extended_context,state,processed_len);
    SHA1Update(&extended_context,payload,sizeof(payload)-1);
    SHA1Final(mac,&extended_context);
    print_bytes(stdout,mac,20,"MAC of hacked string:[","]");

    if (server_verify(forged_message, mac)) {
      printf("Hacked message has a valid MAC\n");
    } else {
      printf("Hacked message has a wrong MAC!!!\n");
    }

    return 0;
}
