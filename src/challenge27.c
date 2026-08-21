#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "print.h"
#include "aes128.h"
#include "pkcs7.h"
#include "random.h"

static uint8_t g_key[AES128_BYTES_IN_BLK];
static uint8_t g_iv[AES128_BYTES_IN_BLK];
static uint8_t g_plaintext[3 * AES128_BYTES_IN_BLK] =
  "First AES block!"
  "Second AES block"
  "Third AES block!";

static uint8_t g_ciphertext[3 * AES128_BYTES_IN_BLK]; 

/*
 * Challenge 27: Recover the key from CBC with IV=Key.
 *
 * Pendiente:
 * - Usar la clave como IV.
 * - Exponer el comportamiento de descifrado vulnerable.
 * - Construir el criptograma manipulado y recuperar la clave.
 */
static int challenge27_recover_key(void)
{
  size_t ciphered_len=0;
  size_t key_len=0,plain_len=0;
  uint8_t key[AES128_BYTES_IN_BLK] = {0};

  printf("=== Reto 27: recuperar la clave de CBC con IV=Key ===\n");
 
  print_bytes_as_ascii(stdout,g_plaintext,sizeof(g_plaintext),"plain:[","]");
  aes128_cbc_encrypt(g_plaintext,sizeof(g_plaintext), g_key, g_iv,
                     g_ciphertext,sizeof(g_ciphertext),&ciphered_len);
  print_bytes(stdout,g_ciphertext,sizeof(g_ciphertext),"ciphered:[",
              "]");
  // modify the second block of the ciphered text
  memset(&g_ciphertext[AES128_BYTES_IN_BLK],0,AES128_BYTES_IN_BLK);
  memcpy(&g_ciphertext[AES128_BYTES_IN_BLK*2],g_ciphertext,AES128_BYTES_IN_BLK);
  print_bytes(stdout,g_ciphertext,sizeof(g_ciphertext),"altered cipher text:[",
              "]");
  aes128_cbc_decrypt(g_ciphertext,sizeof(g_ciphertext),g_key,g_iv,
                     g_plaintext,sizeof(g_plaintext),&plain_len);
  print_bytes(stdout,g_plaintext,plain_len,"plain after attack:[","]");
  size_t i;
  for(i = 0; i < AES128_BYTES_IN_BLK; i++ ) {
    key[i] = g_plaintext[i] ^ g_plaintext[AES128_BYTES_IN_BLK*2+i];
  }

  print_bytes(stdout,key,sizeof(key),"recoverd key:[","]");
  return 0;
}

int main(void)
{
  assert(random_bytes(g_key, sizeof(g_key)) == 0);
  memcpy(g_iv,g_key,AES128_BYTES_IN_BLK);
  print_bytes(stdout,g_key,sizeof(g_key),"key and IV:[","]");

  return challenge27_recover_key();
}
