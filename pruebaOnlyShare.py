import secrets
import os
import hashlib
from pyshamir import split, combine
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
from cryptography.exceptions import InvalidSignature
from tkinter import filedialog, messagebox, simpledialog

#Funcion para hashear el archivo
def calcular_hash(archivo):
    """Calcula el hash SHA-256 de un archivo."""
    sha256 = hashlib.sha256()
    with open(archivo, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

# Función para cifrar el documento y compartir el secreto
def encrypt_and_split_secret(document_data, actual_path,umbral):
    """
    Cifra un documento, divide el secreto en partes y guarda los fragmentos y el documento cifrado.

    Args:
        document_data (bytes): Datos del documento a cifrar.
        actual_path (str): Ruta actual donde se encuentra el archivo original.

    Returns:
        str: Ruta del archivo cifrado guardado.
    """
    # Generar un secreto aleatorio (clave de 128 bits)
    secret = secrets.token_bytes(16)  # 128 bits (16 bytes)
    
    # Cifrar el documento con AES 128-GCM
    nonce, ciphertext, tag = encrypt_aes_gcm(secret, document_data)
    
    # Mostrar el texto cifrado (opcional)
    print("Texto cifrado:", ciphertext.hex())
    global umbral_global 
    umbral_global= umbral
    # Solicitar al usuario el número de partes para dividir el secreto
    num_of_shares = umbral#int(simpledialog.askstring("Entrada", "Introduce el número de partes para dividir el secreto:"))
    
    # Calcular el umbral como la mitad del número de partes + 1
    threshold = num_of_shares // 2 + 1
    
    # Dividir el secreto en partes
    parts = split(secret, num_of_shares, threshold)
    
    # Solicitar al usuario la carpeta donde guardar los fragmentos
    folder_path = filedialog.askdirectory(title="Selecciona la carpeta donde guardar los fragmentos del secreto")
    
    # Verificar si la carpeta existe, si no, crearla
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # Guardar cada parte del secreto en un archivo
    for i, part in enumerate(parts):
        fragment_filename = os.path.join(folder_path, f"fragmento_{i+1}.bin")
        with open(fragment_filename, 'wb') as f:
            f.write(part)
        print(f"Fragmento {i+1} guardado en: {fragment_filename}")
    
    messagebox.showinfo("Éxito", "El secreto ha sido dividido y los fragmentos han sido guardados.")
    
    # Crear el nombre del archivo descifrado basado en actual_path
    decrypted_file_name = os.path.basename(actual_path) + "_cifrado"
    encrypted_file_path = os.path.join(folder_path, decrypted_file_name + ".bin")
    
    # Guardar el documento cifrado
    with open(encrypted_file_path, 'wb') as f:
        f.write(nonce + ciphertext + tag)
    
    messagebox.showinfo("Éxito", f"Documento cifrado guardado en: {encrypted_file_path}")

    return encrypted_file_path
    
# Función para cifrar el texto con AES 128-GCM
def encrypt_aes_gcm(key, data):
    # Generar un nonce aleatorio
    nonce = os.urandom(12)
    
    # Crear un cifrador AES en modo GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Cifrar los datos (sin padding, ya que GCM lo maneja automáticamente)
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Devuelve el nonce, el texto cifrado y el tag (autenticación)
    return nonce, ciphertext, encryptor.tag

# Función para descifrar el documento
def decrypt_document_flow():
    # Solicitar el número de personas presentes
    num_people = int(simpledialog.askstring("Entrada", "Introduce el número de personas presentes:"))
    print("El umbral global es: ",umbral_global)
    # Verificar si el número de personas es suficiente
    if num_people != umbral_global:  # Asegurarse de que haya al menos el umbral de personas
        messagebox.showerror("Error", "El número de personas presentes no es suficiente para descifrar el documento.")
        return
    
    # Cargar las partes del secreto
    secret_parts = []
    for i in range(num_people):
        part_path = filedialog.askopenfilename(title=f"Selecciona la parte del secreto de la persona {i+1}", filetypes=[("Archivos binarios", "*.bin")])
        if part_path:
            with open(part_path, 'rb') as f:
                secret_parts.append(f.read())
        else:
            messagebox.showerror("Error", "No se seleccionó una parte del secreto.")
            return
    
    # Combinar las partes del secreto
    secret = combine(secret_parts)
    
    # Solicitar el documento cifrado
    encrypted_file_path = filedialog.askopenfilename(title="Selecciona el documento cifrado", filetypes=[("Archivos binarios", "*.bin")])
    if not encrypted_file_path:
        messagebox.showerror("Error", "No se seleccionó un documento cifrado.")
        return
    
    # Leer el documento cifrado
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Extraer el nonce, el texto cifrado y el tag
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:-16]
    tag = encrypted_data[-16:]
    
    # Descifrar el documento
    decrypted_data = decrypt_aes_gcm(secret, nonce, ciphertext, tag)
    
    # Guardar el documento descifrado
    decrypted_file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivos de texto", "*.txt")])
    if decrypted_file_path:
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        messagebox.showinfo("Éxito", f"Documento descifrado guardado en: {decrypted_file_path}")
    else:
        messagebox.showerror("Error", "No se seleccionó una ubicación para guardar el documento descifrado.")

# Función para descifrar con AES 128-GCM
def decrypt_aes_gcm(key, nonce, ciphertext, tag):
    # Crear un descifrador AES en modo GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Descifrar los datos (sin necesidad de unpadder porque GCM no requiere padding)
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_data

#Generacion de llaves

def generar_llaves():
    # Generar llave privada
    llave_privada = ec.generate_private_key(ec.SECP224R1())
    llave_publica = llave_privada.public_key()
    
    # Serializar las llaves
    llave_privada_pem = llave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    llave_publica_pem = llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return llave_privada_pem, llave_publica_pem

#Funcion para firmado de documento
def firmar_documento(ruta_documento):
    print("Entro a la funcion firma, esta es la ruta del documento: ",ruta_documento)
    try:
        
        # Pedir al usuario que seleccione el archivo de su llave privada
        ruta_llave_privada = filedialog.askopenfilename(
            title="Selecciona tu llave privada",
            filetypes=[("Archivos PEM", "*.pem"), ("Todos los archivos", "*.*")]
        )
        
        if not ruta_llave_privada:
            messagebox.showwarning("Cancelado", "No se seleccionó un archivo de llave privada.")
            return None

        # Leer la llave privada desde el archivo
        with open(ruta_llave_privada, "rb") as archivo_llave:
            llave_privada = serialization.load_pem_private_key(
                archivo_llave.read(),
                password=None,
                backend=default_backend()
            )
        
        # Leer el contenido del documento
        with open(ruta_documento, "rb") as archivo_documento:
            contenido_documento = archivo_documento.read()
        
        # Generar la firma con ECDSA usando SHA-256
        firma = llave_privada.sign(contenido_documento, ec.ECDSA(hashes.SHA256()))
        print("Se ha firmado: ",firma)
        # Decodificar la firma en los componentes r y s
        r, s = decode_dss_signature(firma)
        print(f"Par r,s:  {r}, {s}")
        # Mostrar mensaje de éxito
        messagebox.showinfo("Éxito", "El documento ha sido firmado exitosamente.")
        
        # Retornar la firma generada
        return r, s

    except Exception as e:
        messagebox.showerror("Error", f"Error al firmar el documento: {e}")
        print(e)
        return None

def verificar_firma(path, public_key_pem, r, s):
    """Función para verificar la firma utilizando la llave pública en formato PEM y los valores r y s."""
    print("Parametros que trae la funcion: ")
    print("Public key PEM: ", public_key_pem)
    print(f" r,s: {r},{s}")
    
    try:
        # Cargar la llave pública desde el formato PEM
        public_key = load_pem_public_key(public_key_pem)

        # Pedir al usuario que seleccione el archivo firmado
        '''
        archivo_firma = filedialog.askopenfilename(title="Seleccionar archivo que fue firmado", filetypes=[("Archivos de texto", "*.txt"),("Todos los Archivos", "*.*")])
        '''
        archivo_firma=path
        if not archivo_firma:
            messagebox.showerror("Error", "No se seleccionó ningún archivo de firma.")
            return

        # Leer el contenido del archivo de firma para obtener el mensaje
        with open(archivo_firma, "rb") as archivo:  # Leer en modo binario
            mensaje = archivo.read()  # El mensaje debe estar en formato de bytes
        print("Mensaje: ",mensaje)

        # Combinar r y s en una firma y codificarla en el formato adecuado
        signature = encode_dss_signature(r, s)

        # Verificar la firma
        public_key.verify(signature, mensaje, ec.ECDSA(hashes.SHA256()))
        return True

    except InvalidSignature:
        messagebox.showerror("Error", "La firma es inválida.")
        return False
    except Exception as e:
        print(f"Error al verificar la firma: {e}")
        messagebox.showerror("Error", f"Error al verificar la firma: {e}")
        return False
