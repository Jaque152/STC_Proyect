from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# --- Función para cifrar un documento ---
def encrypt_file(input_file, output_file, key_file):
    # Generar clave AES de 128 bits y un nonce (12 bytes)
    key = os.urandom(16)  # 16 bytes = 128 bits
    nonce = os.urandom(12)  # 12 bytes es el tamaño recomendado para GCM

    # Leer el contenido del archivo
    with open(input_file, "rb") as file:
        plaintext = file.read()

    # Crear cifrador AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Cifrar el contenido
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Guardar el archivo cifrado
    with open(output_file, "wb") as file:
        file.write(nonce + encryptor.tag + ciphertext)  # Guardar nonce, tag y datos cifrados juntos

    # Guardar la clave en formato Base64
    with open(key_file, "w") as file:
        file.write(base64.b64encode(key).decode('utf-8'))

    print(f"Archivo cifrado guardado en: {output_file}")
    print(f"Clave (en Base64) guardada en: {key_file}")


# --- Función para descifrar un documento ---
def decrypt_file(input_file, output_file, key_file):
    # Leer la clave desde el archivo Base64
    with open(key_file, "r") as file:
        key = base64.b64decode(file.read().encode('utf-8'))

    # Leer el contenido cifrado del archivo
    with open(input_file, "rb") as file:
        data = file.read()

    # Extraer nonce, etiqueta (tag) y texto cifrado
    nonce = data[:12]  # Los primeros 12 bytes son el nonce
    tag = data[12:28]  # Los siguientes 16 bytes son el tag
    ciphertext = data[28:]  # El resto es el texto cifrado

    # Crear descifrador AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descifrar el contenido
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Guardar el contenido descifrado en un archivo
    with open(output_file, "wb") as file:
        file.write(plaintext)

    print(f"Archivo descifrado guardado en: {output_file}")


# --- Ejemplo de uso ---
if __name__ == "__main__":
    # Archivos de entrada y salida
    original_file = "documento.txt"  # Archivo a cifrar (debe existir)
    encrypted_file = "documento_cifrado.bin"  # Archivo cifrado
    decrypted_file = "documento_descifrado.txt"  # Archivo descifrado
    key_file = "clave_base64.txt"  # Archivo donde se guarda la clave en Base64

    # Crear un archivo de prueba
    with open(original_file, "w") as f:
        f.write("Prueba de cifrado de documento.")

    # Cifrar el archivo
    encrypt_file(original_file, encrypted_file, key_file)

    # Descifrar el archivo
    decrypt_file(encrypted_file, decrypted_file, key_file)
