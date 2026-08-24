#include <stdio.h>
#include <stdint.h>
#include "print.h"
#include "sha1.h"

static const uint8_t g_key[] = "YELLOW SUBMARINE";
static uint8_t g_message[] = "The quick brown fox jumps over the lazy dog";

/*
 * Challenge 28: Implement a SHA-1 keyed MAC.
 *
 * Pendiente:
 * - Verificar el MAC de un mensaje.
 */
int main(void)
{
    uint8_t mac[20];
    uint8_t mac2[20];

    printf("=== Reto 28: SHA-1 keyed MAC ===\n");
    printf("Clave de prueba: %zu bytes\n", sizeof(g_key) - 1U);
    printf("Mensaje de prueba: %s \n", g_message);
    sha1_keyed_mac(mac, g_key, sizeof(g_key) - 1U,
                   g_message, sizeof(g_message) - 1U);
    print_bytes(stdout,mac,20,"MAC:[","]");
    // modifico el mensaje
    g_message[3] = '_';
    printf("Mensaje de prueba alterado: %s bytes\n", g_message);
    sha1_keyed_mac(mac2, g_key, sizeof(g_key) - 1U,
                   g_message, sizeof(g_message) - 1U);
    print_bytes(stdout,mac2,20,"MAC msg alterado:[","]");


    return 0;
}
