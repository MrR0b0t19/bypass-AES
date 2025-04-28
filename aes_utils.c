// ==============================================
// Implementación del descifrado AES CBC
// ==============================================

#include "aes_utils.h"
#include <wincrypt.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

void aes_decrypt(unsigned char* ciphertext, DWORD len, unsigned char* key, unsigned char* iv, unsigned char* output) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;

    //  contexto  de cifrado
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;

    //  hash SHA256 de la clave 
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;
    if (!CryptHashData(hHash, key, 16, 0)) goto cleanup;

    // D clave AES-128 a partir del hash
    if (!CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey)) goto cleanup;

    //  IV manualmente
    CryptSetKeyParam(hKey, KP_IV, iv, 0);

    // Copiar el ciphertext a output y descifrar 
    memcpy(output, ciphertext, len);
    DWORD outlen = len;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, output, &outlen)) goto cleanup;

cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
}
