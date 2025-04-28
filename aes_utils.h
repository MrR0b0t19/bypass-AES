// ==============================================
// ==============================================
#ifndef AES_UTILS_H
#define AES_UTILS_H

#include <windows.h>
void aes_decrypt(unsigned char* ciphertext, DWORD len, unsigned char* key, unsigned char* iv, unsigned char* output);

#endif
