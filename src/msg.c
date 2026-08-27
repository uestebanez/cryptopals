#include "msg.h"

#include <stdlib.h>

void cbc_encrypted_message_clear(cbc_encrypted_message_t *message)
{
    free(message->ciphertext);
    message->ciphertext = NULL;
    message->ciphertext_len = 0U;
}
