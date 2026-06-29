#include <stdlib.h>
#include <string.h>
#include "print.h"


static uint8_t g_key[AES128_BYTES_IN_BLK];

static char* profile_for(const char* email)
{
  size_t elen = strlen(email);
  // len 6 -> email=
  // len 17 -> &uid=10&role=user
  size_t total_siz = 6+elen+17+1;

  char* find = strpbrk(email,"&=");
  if( NULL != find ) {
    printf("Found illegal chars '&' or '='\n");
    return NULL;
  }
  char* buf = malloc(total_siz);

  snprintf(buf,total_siz,"email=%s&uid=10&role=user",email);
  return buf;
}

int main(int argc,char** argv)
{
  char* profile;
  assert(0==random_bytes(g_key,sizeof(g_key)));

#if 0
  profile = profile_for("foo@bar.com&role=admin");
  if( NULL != profile ) {
    printf("profile=%s\n",profile);
    free(profile);
  }
#endif

  profile = profile_for("unai@estebanez.me");
  printf("profile=[%s]\n",profile);
  free(profile);
  
  // 13 'A' + "email=" -> 19
  // 18 + "&uid=10&role=" (13chars) -> 32 chars
  profile = profile_for("AAAAAAAAAAAAA");

  //email=AAAAAAAAAAAAA&uid=10&role= -> 32 bytes
  //user -> last block of 4 bytes
  printf("profile=[%s]\n",profile);
  free(profile);

  

  return 0;
}
