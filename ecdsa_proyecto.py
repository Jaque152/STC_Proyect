# -*- coding: utf-8 -*-
"""ECDSA_PROYECTO.ipynb

Automatically generated by Colab.

Original file is located at
    https://colab.research.google.com/drive/1Q-XNluPaaaycwnNSeBqaPk4S5unniWMb
"""

import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
import os

def key_generation():
   # Generar clave privada usando la curva P-224
    private_key = ec.generate_private_key(ec.SECP224R1(), default_backend())
    public_key = private_key.public_key()

    # Obtener los valores numéricos de la clave privada y pública
    private_numbers = private_key.private_numbers()
    public_numbers = public_key.public_numbers()

    # Convertir los valores a bytes
    private_key_bytes = private_numbers.private_value.to_bytes(28, byteorder="big")
    public_key_x_bytes = public_numbers.x.to_bytes(28, byteorder="big")
    public_key_y_bytes = public_numbers.y.to_bytes(28, byteorder="big")

    # Codificar en Base64
    private_key_base64 = base64.b64encode(private_key_bytes).decode("utf-8")
    public_key_x_base64 = base64.b64encode(public_key_x_bytes).decode("utf-8")
    public_key_y_base64 = base64.b64encode(public_key_y_bytes).decode("utf-8")

    # Guardar la llave privada en un archivo
    with open("private_key.txt", "w") as private_file:
        private_file.write(f"PrK: {private_key_base64}\n")

    # Guardar la llave pública (coordenadas x, y) en otro archivo
    with open("public_key.txt", "w") as public_file:
        public_file.write(f"PKX: {public_key_x_base64}\n")
        public_file.write(f"PKY: {public_key_y_base64}\n")

def sign_message(file_path):
    # Leer la llave privada desde el archivo
    with open("private_key.txt", "r") as private_file:
        private_key_base64 = private_file.readline().strip().split(": ")[1]

    # Decodificar la llave privada desde Base64
    private_key_bytes = base64.b64decode(private_key_base64)

    # Reconstruir la llave privada
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, byteorder="big"),
        ec.SECP224R1(),
        default_backend()
    )

    #
    with open(file_path, "rb") as message_file:
        message_bytes = message_file.read()

    # Generar la firma con ECDSA usando SHA-256
    signature = private_key.sign(message_bytes, ec.ECDSA(hashes.SHA256()))
    # Dividir la firma en los componentes r y s
    r, s = decode_dss_signature(signature)

    # Crear un nuevo nombre de archivo
    signed_file_path = f"{os.path.splitext(file_path)[0]}_firmado{os.path.splitext(file_path)[1]}"

    # Agregar firma al final del nuevo archivo
    with open(signed_file_path, "wb") as signed_file:
        signed_file.write(message_bytes)
        signed_file.write(r.to_bytes(32, byteorder="big"))
        signed_file.write(s.to_bytes(32, byteorder="big"))

    return r, s, signed_file_path

def verify_signature(file_path):
    # Leer la llave pública desde el archivo
    with open("public_key.txt", "r") as public_file:
        public_key_x_base64 = public_file.readline().strip().split(": ")[1]
        public_key_y_base64 = public_file.readline().strip().split(": ")[1]

    # Decodificar la llave pública desde Base64
    public_key_x_bytes = base64.b64decode(public_key_x_base64)
    public_key_y_bytes = base64.b64decode(public_key_y_base64)

    # Reconstruir la llave pública
    public_numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(public_key_x_bytes, byteorder="big"),
        int.from_bytes(public_key_y_bytes, byteorder="big"),
        ec.SECP224R1()
    )
    public_key = public_numbers.public_key(default_backend())

    with open(file_path, "rb") as message_file:
        message_bytes = message_file.read()

    # Leer los últimos 64 bytes como la firma
    r = int.from_bytes(message_bytes[-64:-32], byteorder="big")
    s = int.from_bytes(message_bytes[-32:], byteorder="big")

    signature = encode_dss_signature(r, s)

    try:
        public_key.verify(signature, message_bytes[:-64], ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False

# Generar llaves
key_generation()

# Firmar un mensaje desde un archivo
file_to_sign = input("Introduce la ruta del archivo para firmar: ")
r, s, signed_file_path = sign_message(file_to_sign)
print(f"Archivo firmado creado: {signed_file_path} con firma: (r, s) = ({r}, {s})")

# Verificar la firma de un mensaje desde un archivo
file_to_verify = input("Introduce la ruta del archivo que fue firmado: ")
is_valid = verify_signature(file_to_verify)

if is_valid:
    print("Firma verificada correctamente.")
else:
    print("La verificación de la firma falló.")