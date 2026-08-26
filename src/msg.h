#ifndef MSG_H
#define MSG_H

#include <stdint.h>

typedef struct {
    const uint8_t *bytes;
    uint32_t length;
} message_t;

#endif /* MSG_H */
