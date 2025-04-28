# ==============================================
# Compilar todos los módulos y generar shell_container.dat final
# Requisitos: x86_64-w64-mingw32-gcc, bash
# ==============================================

#!/bin/bash
set -e

# salida
OUT_DIR="build"
mkdir -p $OUT_DIR

# Compilación de DLLs individuales
echo "[+] Compilando stage1.dll..."
x86_64-w64-mingw32-gcc -shared -s -O2 stage1.c -o $OUT_DIR/stage1.dll

echo "[+] Compilando stage2.dll..."
x86_64-w64-mingw32-gcc -shared -s -O2 stage2.c aes_utils.c -o $OUT_DIR/stage2.dll -ladvapi32

# Compilar loader.exe
echo "[+] Compilando loader.exe..."
x86_64-w64-mingw32-gcc -s -O2 loader.c reflective_loader.c -o $OUT_DIR/loader.exe

# Generar archivo contenedor
echo "[+] Generando shell_container.dat..."
cat $OUT_DIR/stage1.dll $OUT_DIR/stage2.dll > $OUT_DIR/shell_container.dat

echo "[+] Build finalizado. Ejecutable: $OUT_DIR/loader.exe"
echo "    Contenedor:   $OUT_DIR/shell_container.dat"

# Opcional: puedes ejecutar el binario en Windows para prueba
# wine $OUT_DIR/loader.exe
