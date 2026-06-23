#ifndef PRINT_H
#define PRINT_H

/**
 * \brief print an hexadecimal ascii string as an ascii output
 * e.g. 6162... -> ab..
 */
void print_hex_as_ascii(const char* hex);

/**
 * \brief print a buffer of bytes in hex 
 * \param file file to print into
 * \param bytes buffer with the bytes
 * \param len length of the binary buffer
 * \param prefix, optional parameter (can be NULL) to add a prefix to the print
 */
void print_bytes(FILE* file,const uint8_t* bytes,size_t len,const char* prefix);

#endif
