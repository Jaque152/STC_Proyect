import secrets
import os
import hashlib
from pyshamir import split, combine
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
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
def encrypt_and_split_secret(document_data):
    
    # Generar un secreto aleatorio (clave de 128 bits)
    secret = secrets.token_bytes(16)  # 128 bits (16 bytes)
    
    # Cifrar el documento con AES 128-GCM
    nonce, ciphertext, tag = encrypt_aes_gcm(secret, document_data)
    
    # Mostrar el texto cifrado (opcional)
    print("Texto cifrado:", ciphertext.hex())
    
    # Solicitar al usuario el número de partes para dividir el secreto
    num_of_shares = int(simpledialog.askstring("Entrada", "Introduce el número de partes para dividir el secreto:"))
    
    # Calcular el umbral como la mitad del número de partes + 1
    threshold = num_of_shares//2+1
    
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
    
    # Guardar el documento cifrado
    encrypted_file_path = os.path.join(folder_path, "documento_cifrado.bin")
    with open(encrypted_file_path, 'wb') as f:
        f.write(nonce + ciphertext + tag)
    messagebox.showinfo("Éxito", f"Documento cifrado guardado en: {encrypted_file_path}")

    
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
    
    # Verificar si el número de personas es suficiente
    if num_people != 4:  # Asegurarse de que haya al menos el umbral de personas
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
