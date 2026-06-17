#ifndef _FIXED_XOR_H
#define _FIXED_XOR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief apply an xor cipher between input and key of the same length
 * \param input input string in ascii hexadecimal format (two digits per byte)
 * \param key input key string in ascii hexadecimal format
 * \para output buffer to store the ciphering
 * \remarks all buffers must have same capacity
 */
int fixed_xor(const char* input,const char* key, char* output);
#ifdef __cplusplus
}
#endif

#endif /* FIXED_XOR_H */
