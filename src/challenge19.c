#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "random.h"
#include "aes128.h"
#include "base64.h"
#include "print.h"
#include "score.h"

#define MAX_ENTRIES 40

static const char* g_strings[MAX_ENTRIES] = { 
"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
"U2hlIHJvZGUgdG8gaGFycmllcnM/",
"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
};

static uint8_t plain[40][256];
static size_t plain_len[40];
static uint8_t cipher[40][256];
static size_t cipher_len[40];
static uint8_t g_key[AES128_BYTES_IN_BLK];

int main(int argc,char** argv)
{
  // key to find out
  static uint8_t key[256] = {0};
  static size_t key_len = 0;

  size_t max_cipher_len = 0;
  srand((unsigned int)time(NULL));
  assert(0==random_bytes(g_key,sizeof(g_key)));
  
  for(int i = 0; i < MAX_ENTRIES; i++ ) {
    base642bin(g_strings[i],plain[i],&plain_len[i]); 
    printf("Plain len: %d -> [%.*s]\n",(int)plain_len[i],(int)plain_len[i],
           plain[i]);
    aes128_ctr_crypt(plain[i],plain_len[i],g_key,0,
                     cipher[i],sizeof(cipher[i]),
                     &cipher_len[i]);
    printf("Cipher len:%d\n",(int)cipher_len[i]);
    if( cipher_len[i] > max_cipher_len )
      max_cipher_len = cipher_len[i];
  }
  printf("Max cipher len=%zu\n",max_cipher_len);
  key_len = max_cipher_len;

  for (size_t pos = 0; pos < key_len; pos++) {
    int best_score = -999999;
    uint8_t best_key_char = 0;

    for (int k = 0; k < 256; k++) {
      int score = 0;

      for (size_t i = 0; i < MAX_ENTRIES; i++) {
          if (pos < cipher_len[i] ) {
              uint8_t p = cipher[i][pos] ^ k;
              score += score_char((char)p);
          }
      }
      if (score > best_score) {
          best_score = score;
          best_key_char = (uint8_t)k;
      }
    }
    key[pos] = best_key_char;
  }

  for (size_t i = 0; i < MAX_ENTRIES; i++) {
    printf("[%zu] ", i);

    for (size_t pos = 0; pos < cipher_len[i]; pos++) {
        uint8_t p = cipher[i][pos] ^ key[pos];

        if (p >= 0x20 && p <= 0x7e) {
            printf("%c", p);
        } else {
            printf(".");
        }
    }
    printf("\n");
  }

  print_bytes(stdout,key,key_len,"key:");

  return 0;
}

