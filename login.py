import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import mysql.connector
import json
import os
import hashlib
from pruebaOnlyShare import encrypt_and_split_secret, decrypt_document_flow, calcular_hash

# Variables globales
current_user_id = None  # Variable para almacenar el ID del usuario

# Funciones de base de datos
def cargar_configuracion():
    """Carga la configuración de la base de datos desde un archivo JSON."""
    try:
        ruta_config = os.path.join("config", "db_config.json")
        with open(ruta_config, "r") as archivo:
            config = json.load(archivo)
        return config
    except FileNotFoundError:
        messagebox.showerror("Error", "No se encontró el archivo de configuración 'db_config.json'.")
        return None
    except json.JSONDecodeError:
        messagebox.showerror("Error", "El archivo de configuración no tiene un formato JSON válido.")
        return None

def conectar_base_datos():
    """Establece la conexión con la base de datos."""
    db_config = cargar_configuracion()
    if not db_config:
        return None
    try:
        conexion = mysql.connector.connect(**db_config)
        return conexion
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al conectar con la base de datos: {e}")
        return None

def hashear_contraseña(contraseña):
    """Hashea la contraseña usando SHA-256."""
    sha256 = hashlib.sha256()
    sha256.update(contraseña.encode('utf-8'))
    return sha256.hexdigest()

def registrar_usuario(nombre_usuario, contraseña, confirmar_contraseña, rol, nombre_completo):
    """Registra un usuario en la base de datos."""
    if contraseña != confirmar_contraseña:
        messagebox.showerror("Error", "Las contraseñas no coinciden. Intente nuevamente.")
        return
    
    if rol not in ['cliente', 'abogado']:
        messagebox.showerror("Error", "Rol no válido. Debe ser 'cliente' o 'abogado'")
        return

    contraseña_hash = hashear_contraseña(contraseña)
    
    conexion = conectar_base_datos()
    if not conexion:
        return

    cursor = conexion.cursor()
    
    try:
        query = """
        INSERT INTO Usuario (nombre_usuario, contraseña_hash, rol, nombre_completo)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (nombre_usuario, contraseña_hash, rol, nombre_completo))
        conexion.commit()
        messagebox.showinfo("Éxito", f"Usuario '{nombre_usuario}' registrado exitosamente.")
        mostrar_pantalla_bienvenida()
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al registrar el usuario: {e}")
    finally:
        cursor.close()
        conexion.close()

def iniciar_sesion(nombre_usuario, contraseña):
    """Inicia sesión de un usuario en la base de datos."""
    global current_user_id  # Usar la variable global para almacenar el ID del usuario
    conexion = conectar_base_datos()
    if not conexion:
        return False
    
    cursor = conexion.cursor(dictionary=True)
    
    try:
        query = "SELECT * FROM Usuario WHERE nombre_usuario = %s"
        cursor.execute(query, (nombre_usuario,))
        usuario = cursor.fetchone()
        if usuario and hashear_contraseña(contraseña) == usuario['contraseña_hash']:
            current_user_id = usuario['id_usuario']  # Guardar el ID del usuario
            rol = usuario['rol']  # Obtener el rol del usuario desde la base de datos
            messagebox.showinfo("Éxito", "Inicio de sesión exitoso.")
            # Redirigir a la pantalla correspondiente según el rol
            if rol == "cliente":
                show_client_screen()
            elif rol == "abogado":
                show_lawyer_screen()
            elif rol == "administrador":
                show_admin_screen()
            return True
        else:
            messagebox.showerror("Error", "Usuario o contraseña incorrectos.")
            return False
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al consultar el usuario: {e}")
        return False
    finally:
        cursor.close()
        conexion.close()

# Funciones de interfaz
def mostrar_pantalla_bienvenida():
    """Muestra la pantalla de bienvenida con los botones de ingresar y registrarse."""
    clear_screen()
    tk.Label(root, text="Bienvenido al Sistema de Firma y Cifrado de Documentos", font=("Arial", 16)).pack(pady=20)
    tk.Button(root, text="Ingresar", command=mostrar_login_screen).pack(pady=10)
    tk.Button(root, text="Registrarse", command=mostrar_formulario_registro).pack(pady=10)

def mostrar_login_screen():
    """Muestra la pantalla de inicio de sesión."""
    clear_screen()
    tk.Label(root, text="Inicio de Sesión", font=("Arial", 16)).pack(pady=10)
    global user_entry, pass_entry
    tk.Label(root, text="Usuario").pack(pady=5)
    user_entry = tk.Entry(root)
    user_entry.pack(pady=5)
    tk.Label(root, text="Contraseña").pack(pady=5)
    pass_entry = tk.Entry(root, show="*")
    pass_entry.pack(pady=5)
    tk.Button(root, text="Iniciar Sesión", command=lambda: iniciar_sesion(user_entry.get(), pass_entry.get())).pack(pady=10)
    tk.Button(root, text="Regresar", command=mostrar_pantalla_bienvenida).pack(pady=10)

def mostrar_formulario_registro():
    """Muestra el formulario de registro de usuario."""
    clear_screen()
    tk.Label(root, text="Registro de Usuario", font=("Arial", 16)).pack(pady=10)

    tk.Label(root, text="Nombre Completo").pack(pady=5)
    nombre_completo_entry = tk.Entry(root)
    nombre_completo_entry.pack(pady=5)

    tk.Label(root, text="Nombre de Usuario").pack(pady=5)
    nombre_usuario_entry = tk.Entry(root)
    nombre_usuario_entry.pack(pady=5)

    tk.Label(root, text="Contraseña").pack(pady=5)
    contraseña_entry = tk.Entry(root, show="*")
    contraseña_entry.pack(pady=5)

    tk.Label(root, text="Confirmar Contraseña").pack(pady=5)
    confirmar_contraseña_entry = tk.Entry(root, show="*")
    confirmar_contraseña_entry.pack(pady=5)

    tk.Label(root, text="Rol").pack(pady=5)
    rol_var = tk.StringVar()
    rol_abogado = tk.Radiobutton(root, text="Abogado", variable=rol_var, value="abogado")
    rol_cliente = tk.Radiobutton(root, text="Cliente", variable=rol_var, value="cliente")
    rol_abogado.pack(pady=5)
    rol_cliente.pack(pady=5)

    tk.Button(root, text="Registrar", command=lambda: registrar_usuario(
        nombre_usuario_entry.get(),
        contraseña_entry.get(),
        confirmar_contraseña_entry.get(),
        rol_var.get(),
        nombre_completo_entry.get()
    )).pack(pady=10)
    tk.Button(root, text="Regresar", command=mostrar_pantalla_bienvenida).pack(pady=10)

#Funcionalidad documento
def guardar_documento(ruta_archivo, hash_documento, id_cliente):
    """Guarda el documento en la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return
    
    cursor = conexion.cursor()
    
    try:
        query = """
        INSERT INTO Documento (id_cliente, ruta_archivo, hash)
        VALUES (%s, %s, %s)
        """
        cursor.execute(query, (id_cliente, ruta_archivo, hash_documento))
        conexion.commit()
        messagebox.showinfo("Éxito", "Documento cargado exitosamente.")
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al cargar el documento: {e}")
    finally:
        cursor.close()
        conexion.close()
def cargar_documento():
    """Permite al abogado cargar un documento y guardarlo en la base de datos."""
    # Abrir el cuadro de diálogo para seleccionar el archivo
    archivo = filedialog.askopenfilename(title="Seleccionar Documento", filetypes=[("Archivos PDF", "*.pdf"), ("Todos los archivos", "*.*")])
    if archivo:
        # Calcular el hash del archivo
        hash_documento = calcular_hash(archivo)
        # Guardar el documento en la base de datos
        guardar_documento(archivo, hash_documento, current_user_id)
       
def cargar_documentos_disponibles():
    """Carga los documentos disponibles para el abogado desde la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return []
    
    cursor = conexion.cursor(dictionary=True)
    
    try:
        query = "SELECT * FROM Documento WHERE id_cliente = %s"
        cursor.execute(query, (current_user_id,))  # Asegúrate de que current_user_id esté definido
        documentos = cursor.fetchall()
        return documentos
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al cargar los documentos: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()

def enviar_documentos_disponibles(callback):
    """Permite al abogado seleccionar un documento de los disponibles y ejecutar el cifrado."""
    documentos = cargar_documentos_disponibles()
    
    if not documentos:
        messagebox.showerror("Error", "No tienes documentos disponibles para cifrar.")
        return
    
    # Crear una ventana para mostrar los documentos disponibles
    ventana_seleccion = tk.Toplevel()
    ventana_seleccion.title("Seleccionar Documento")
    
    # Crear un Listbox para mostrar los documentos
    document_names = [doc['ruta_archivo'] for doc in documentos]
    listbox = tk.Listbox(ventana_seleccion, height=10, width=50)
    for doc_name in document_names:
        listbox.insert(tk.END, doc_name)
    listbox.pack(padx=10, pady=10)  # Asegurarse de que el Listbox se muestre
    
    # Función para manejar la selección del documento
    def seleccionar_documento():
        selected_doc_index = listbox.curselection()
        if not selected_doc_index:
            messagebox.showerror("Error", "No se ha seleccionado ningún documento.")
            return
        
        selected_doc = document_names[selected_doc_index[0]]
        document = next(doc for doc in documentos if doc['ruta_archivo'] == selected_doc)
        
        # Leer el contenido del documento
        with open(document['ruta_archivo'], 'rb') as f:
            document_data = f.read()
        
        ventana_seleccion.destroy()  # Cerrar la ventana de selección
        
        # Llamar al callback para continuar con el cifrado
        callback(document_data)
    
    # Botón para seleccionar el documento
    btn_seleccionar = tk.Button(ventana_seleccion, text="Seleccionar", command=seleccionar_documento)
    btn_seleccionar.pack(pady=10)
    
    ventana_seleccion.mainloop()

def cifrar_doc(document_data):
    """Cifra el documento seleccionado y realiza la división del secreto."""
    # Llamar a la función de cifrado y dividir el secreto
    encrypt_and_split_secret(document_data)

# Función para llamar a la selección de documento y continuar con el cifrado
def seleccionar_y_cifrar():
    enviar_documentos_disponibles(cifrar_doc)

# Pantalla principal para cliente
def show_client_screen():
    clear_screen()
    tk.Label(root, text="Bienvenido, Cliente", font=("Arial", 16)).pack(pady=10)
    tk.Button(root, text="Generar Par de Llaves", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Compartir Secreto", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Cerrar Sesión", command=mostrar_pantalla_bienvenida).pack(pady=10)

# Pantalla principal para abogado
def show_lawyer_screen():
    clear_screen()
    tk.Label(root, text="Bienvenido, Abogado", font=("Arial", 16)).pack(pady=10)
    # Botón para cifrar documento
    tk.Button(root, text="Cargar Documento", command=cargar_documento).pack(pady=5)
    tk.Button(root, text="Cifrar Documento", command=seleccionar_y_cifrar).pack(pady=5)
    tk.Button(root, text="Generar Par de Llaves", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Firmar Documento", command=lambda: None).pack(pady=5)
    # Botón para visualizar documento
    tk.Button(root, text="Visualizar Documento", command=decrypt_document_flow).pack(pady=5)
    tk.Button(root, text="Cerrar Sesión", command=mostrar_login_screen).pack(pady=10)

# Pantalla principal para administrador
def show_admin_screen():
    clear_screen()
    tk.Label(root, text="Bienvenido, Administrador", font=("Arial", 16)).pack(pady=10)
    tk.Button(root, text="Generar Clave y Compartir Secreto", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Eliminar Usuario", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Recuperar Contraseña de Usuario", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Cerrar Sesión", command=mostrar_pantalla_bienvenida).pack(pady=10)

# Función para eliminar pantalla anterior
def clear_screen():
    for widget in root.winfo_children():
        widget.destroy()

# Declaración inicial de la interfaz
root = tk.Tk()
root.title("Sistema de Firma y Cifrado de Documentos")
root.geometry("800x300")

# Mostrar la pantalla de bienvenida
mostrar_pantalla_bienvenida()

# Ejecución de la aplicación
root.mainloop()
