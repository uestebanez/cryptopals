#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "base64.h"

#define LINE_SIZE 60

int main(int argc,char** argv)
{
  FILE* file;
  char line[LINE_SIZE+2];

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
  size_t textsiz = 0;
  char* text=NULL;

  while(NULL != fgets(line,sizeof(line),file) ) {
    line[strcspn(line, "\n")] = '\0';
    llen = strlen(line);
    text = realloc(text,llen+textsiz+1);
    strcat(text,line);
    textsiz+=llen;
  }
  
  size_t binsiz = base64_binsize(text);
  uint8_t* bin = calloc(1,binsiz);
  base642bin(text,bin);
  uint8_t plain_text[binsiz+EVP_CIPHER_block_size(EVP_aes_128_ecb())];
  int outl = 0;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL,"YELLOW SUBMARINE", NULL);
  if( 1 != EVP_DecryptUpdate(ctx,plain_text,&outl,bin,binsiz) ) {
    printf("Error updating\n");
    goto end;
  }
  int final_len = 0;
  if( 1 != EVP_DecryptFinal_ex(ctx, plain_text + outl, &final_len) ) {
    printf("Error in Decrypt Final\n");
    goto end;
  }
  fwrite(plain_text,1,binsiz,stdout); 
 
end:
  EVP_CIPHER_CTX_free(ctx);
  free(text);
  free(bin);
  fclose(file);
  return 0;
}
