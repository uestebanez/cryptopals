#ifndef HAMMING_H
#define HAMMING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \brief Calculate the hamming distance between two binary strings
 * \param a binary string
 * \param b binary string
 * \param len length of both binary strings (must be same length)
 * \return hamming distance
 */
size_t hamming_distance(const uint8_t* a,const uint8_t* b,size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
