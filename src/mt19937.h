#ifndef _MT19937_H
#define _MT19937_H

#include <stdint.h>
#include <stdlib.h>
/** 
 * Note: This code has been created using source code from Internet
 */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    uint32_t mt[624];
    size_t index;
} mt19937_t;

void mt19937_seed(mt19937_t *rng, uint32_t seed);
uint32_t mt19937_extract(mt19937_t *rng);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

