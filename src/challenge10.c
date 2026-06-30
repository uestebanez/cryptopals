#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "convert.h"
#include "base64.h"
#include "print.h"

uint8_t g_key[16] = "YELLOW SUBMARINE";
uint8_t g_iv[16] = {0};

static void buffer_xor(uint8_t* buf,size_t bufsiz,const uint8_t* xor)
{
  size_t i;
  for( i = 0; i < bufsiz; i++ ) {
    buf[i] ^= xor[i];
  }
}

static 
int aes128_cbc_decrypt(const uint8_t* ciphered,size_t ciphered_len,
                       uint8_t key[16],uint8_t iv[16],uint8_t* plain)
{
  int r = 0;
  if (ciphered == NULL || key == NULL || iv == NULL || plain == NULL)
    return -1;
  if (ciphered_len == 0 || ciphered_len % 16 != 0)
    return -1;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  if( NULL == ctx )
    return -1;
  
  if( 1 != 
      EVP_DecryptInit_ex(ctx,EVP_aes_128_ecb(),NULL,key,NULL) ) {
    r = -1;
    goto end;
  }
  
  if( 1 != EVP_CIPHER_CTX_set_padding(ctx, 0) ) {
    r = -1;
    goto end;
  }

  size_t blocks = ciphered_len / 16;
  int outl = 0;
  size_t idx = 0;
  size_t i;
  for( i = 0; i < blocks; i++ ) {
    if( 1 != EVP_DecryptUpdate(ctx,&plain[idx],&outl,&ciphered[idx],16) ) {
      printf("Error updating\n");
      r = -1;
      goto end;
    }
    if( i > 0 ) { // rest of the blocks except the first one
      buffer_xor(&plain[idx],16,&ciphered[idx-16]);
    } else {// first block,xor with IV
      buffer_xor(&plain[idx],16,iv);
    }
    idx += 16;
  }
end:
  EVP_CIPHER_CTX_free(ctx);
  return r;
}

int main(int argc,char** argv)
{
  FILE* file;

  if( argc < 2 ) {
    printf("I need a file to parse\n");
    return -1;
  }
  file = fopen(argv[1],"r");
  if( NULL == file ) {
    printf("Failure opening the file\n");
    return -2;
  }
  
  size_t llen; // line len
  char* line=NULL;
  size_t lineno=0;
  uint8_t* base64text = NULL;
  size_t base64len = 0;
  uint8_t* ciphered_text = NULL;
  size_t ciphered_len = 0;
  uint8_t* plain_text = NULL;

  while(getline(&line,&llen,file) > 0 ) {
    lineno++;
    line[strcspn(line, "\n")] = '\0';
    llen = strlen(line);

    base64text = realloc(base64text,base64len+llen);
    memcpy(&base64text[base64len],line,llen);
    base64len+=llen;

    free(line);
    line = NULL;
    llen = 0;
  }
  ciphered_len = base64_binsize(base64text);
  printf("Base64 content len=%zu in binary=%zu\n",base64len,ciphered_len);
  ciphered_text = malloc(ciphered_len);
  base642bin(base64text,ciphered_text,NULL);
  plain_text = malloc(ciphered_len);
  if( 0 != 
      aes128_cbc_decrypt(ciphered_text,ciphered_len,g_key,g_iv,plain_text) ) {
    printf("Error decrypting\n");
  }
  fwrite(plain_text,1,ciphered_len,stdout);
  free(plain_text);
  free(ciphered_text);
  free(base64text);
  fclose(file);
  return 0;
}
