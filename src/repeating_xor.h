#ifndef _REPEATING_XOR_H
#define _REPEATING_XOR_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * \brief applies a xor key that could be shorter than the input
 * \param input input string as hexadecimal ascii chars
 * \param key input key string as hexadecimal ascii chars
 * \param output ciphered output
 */ 
int repeating_xor(const char* input,const char* key, char* output);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
