#ifndef _FIXED_XOR_H
#define _FIXED_XOR_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief apply an xor cipher between input and key of the same length
 * \param input input string in ascii hexadecimal format (two digits per byte)
 * \param key input key string in ascii hexadecimal format
 * \param output buffer to store the ciphering
 * \return 0 if sucess, -1 if error
 * \remarks all buffers must have same capacity
 */
int fixed_xor(const char* input,const char* key, char* output);

/**
 * \brief apply an xor cipher between input and key of the same length
 * \param input input bytes 
 * \param key input key bytes
 * \param key_len size of the key (and the input)
 * \param output buffer to store the ciphering
 * \return 0 if sucess, -1 if error
 * \remarks all buffers must have same capacity
 */
int fixed_xor_bin(const uint8_t* input, const uint8_t* key,size_t keylen,
                  uint8_t* output);


/**
 * \brief try to decipher a text using fixed xor of same length that text.
 * \param line string with the text to decipher. hexadecimal ascii representation
 * \param best_text buffer to store best text that we think is the deciphered text
 * \param bkey. optional(can be NULL). pointer to create a buffer with the best key. This buffer must be freed with "free" after using it.
 * \return score. Integer value that represent the score given to the test. 
 * This score represent a value of confidence. See "score.h" and "score.c"
 */
int fixed_xor_try(const char* line,char* best_text,char** bkey);

/**
 * \brief try to decipher a binary buffer using fixed xor of same length that
 * buf.
 * \param buf bytes to decipher. 
 * \param size size of the buffer 
 * \param bkey pointer to store the best key byte (all bytes are same,so only need to return one) 
 * \return score. Integer value that represent the score given to the test. 
 * This score represent a value of confidence. See "score.h" and "score.c"
 */
int fixed_xor_bin_try(uint8_t* buf,size_t size,uint8_t* bkey);


#ifdef __cplusplus
}
#endif

#endif /* FIXED_XOR_H */
