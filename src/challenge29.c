#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#include "print.h"
#include "sha1.h"

static const uint8_t g_key[] = "YELLOW SUBMARINE";
static uint8_t g_message[] = "The quick brown fox jumps over the lazy dog";

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
    uint64_t original_length = (sizeof(g_key) - 1U) +
        (sizeof(g_message) - 1U);
    uint32_t padding_len;
    const char payload[] = ";admin=true";
    char hacked_msg[(sizeof(g_message) - 1U) + SHA1_PADDING_MAX_BYTES +
                    (sizeof(payload) - 1U)];


    printf("=== Reto 29: SHA-1 length extension attack ===\n");


    printf("Mensaje de prueba: %s \n", g_message);

    sha1_keyed_mac(mac, g_key, sizeof(g_key) - 1U,
                   g_message, sizeof(g_message) - 1U);
    print_bytes(stdout,mac,20,"MAC:[","]");
    if( true == sha1_keyed_mac_verify(mac,g_key,sizeof(g_key)-1,
                          g_message,sizeof(g_message)-1) ) {
      printf("MAC is right\n");
    } else {
      printf("Wrong MAC!!!\n");
    }
    sha1_mac_to_state(mac, state);
    padding_len = sha1_padding(padding, original_length);
    printf("Padding len=%"PRIu32"\n",padding_len);

    char* hacked_ptr = hacked_msg;
    memcpy(hacked_ptr,g_message,sizeof(g_message)-1);
    hacked_ptr+=sizeof(g_message)-1;
    memcpy(hacked_ptr,padding,padding_len);
    hacked_ptr+=padding_len;
    memcpy(hacked_ptr,payload,sizeof(payload)-1);
    hacked_ptr+=sizeof(payload)-1;

    uint64_t processed_len = padding_len+sizeof(g_message)-1+sizeof(g_key)-1;
    printf("Processed len=%"PRIu64"\n",processed_len);

    SHA1InitV2(&extended_context,state,processed_len);
    SHA1Update(&extended_context,payload,sizeof(payload)-1);
    SHA1Final(mac,&extended_context);
    print_bytes(stdout,mac,20,"MAC of hacked string:[","]");

    if( true == sha1_keyed_mac_verify(mac,g_key,sizeof(g_key)-1,
                                      hacked_msg,hacked_ptr-hacked_msg) ) {
      printf("Hacked message has a valid MAC\n");
    } else {
      printf("Hacked message has a wrong MAC!!!\n");
    }

    return 0;
}
