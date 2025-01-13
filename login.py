import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import mysql.connector
import json
import os
import hashlib
import base64	
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import serialization
from pruebaOnlyShare import verificar_firma,firmar_documento,encrypt_and_split_secret, decrypt_document_flow, calcular_hash, generar_llaves
from cryptography.hazmat.backends import default_backend
# Variables globales
current_user_id = None  # Variable para almacenar el ID del usuario
current_user_type = None #Variable para almacenar el rol del usuario

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

def set_user_type(user_type):
    global current_user_type
    current_user_type = user_type

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
                set_user_type(rol)
            elif rol == "abogado":
                show_lawyer_screen()
                set_user_type(rol)
            elif rol == "administrador":
                show_admin_screen()
                set_user_type(rol)
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
        query = "SELECT * FROM Documento WHERE id_cliente = %s AND estado = %s"
        cursor.execute(query, (current_user_id,'pendiente'))  # Asegúrate de que current_user_id esté definido
        documentos = cursor.fetchall()
        return documentos
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al cargar los documentos: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()

#Carga de documentos disponibles con estado "cifrado"
def cargar_documentos_disponibles_para_firmar():
    """Carga los documentos disponibles para el abogado desde la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return []
    
    cursor = conexion.cursor(dictionary=True)
    
    try:
        query = """
            SELECT d.id_documento, d.ruta_archivo, d.estado
            FROM Documento d
            LEFT JOIN Firma f ON d.id_documento = f.id_documento AND f.id_usuario = %s
            INNER JOIN Asignacion a ON d.id_documento = a.id_documento
            WHERE f.id_firma IS NULL AND a.id_abogado = %s;
            """
        
        #query = "SELECT * FROM Documento WHERE id_cliente = %s AND estado = %s"
        cursor.execute(query, (current_user_id,current_user_id))  # Asegúrate de que current_user_id esté definido
        documentos = cursor.fetchall()
        print(documentos)
        return documentos
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al cargar los documentos: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()

def cargar_documentos_disponibles_cliente():
    """Carga los documentos disponibles para el cliente desde la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return []
    
    cursor = conexion.cursor(dictionary=True)
    try:
        print("Realizando consulta a la base en cliente firma")
        query = "SELECT * FROM Documento WHERE id_documento IN (SELECT id_documento FROM Asignacion WHERE id_cliente = %s) AND estado IN (%s, %s)"
        cursor.execute(query, (current_user_id,'cifrado','firmado_abogado'))  # Asegúrate de que current_user_id esté definido
        documentos = cursor.fetchall()  
        print("Retornando resultados en cliente firma",documentos)
        return documentos
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al cargar los documentos: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()

def enviar_documentos_disponibles(callback, num):
    """Permite al abogado seleccionar un documento de los disponibles y ejecutar el cifrado."""
    print("Funcion a ejecutar: ",num)
    if num == 1:
        print("Opcion numero: ",num)
        documentos = cargar_documentos_disponibles()
    elif num == 2:
        print("Opcion numero: ",num)
        documentos = cargar_documentos_disponibles_para_firmar()
    elif num==3:
        print("Opcion numero: ",num)
        documentos = cargar_documentos_disponibles_cliente()
    if not documentos:
        messagebox.showerror("Error", "No tienes documentos cargados.")
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
        callback(document_data, document['ruta_archivo'])
    
    # Botón para seleccionar el documento
    btn_seleccionar = tk.Button(ventana_seleccion, text="Seleccionar", command=seleccionar_documento)
    btn_seleccionar.pack(pady=10)
    
    ventana_seleccion.mainloop()

def cifrar_doc(document_data, actual_path):
    """Cifra el documento seleccionado y realiza la división del secreto."""
    conexion = conectar_base_datos()
    if not conexion:
        return []

    cursor = conexion.cursor()
    print("Realizando consulta en cifrado")
    cursor.execute("SELECT id_documento FROM Documento WHERE ruta_archivo = %s", (actual_path,))
    resultado = cursor.fetchone()

    if not resultado:
        messagebox.showerror("Error", "No se encontró el documento en la base de datos.")
        return

    id_doc = resultado[0]
    print("Id del documento: ", id_doc)

    # Contar el número de asignados al documento en la tabla Asignacion
    cursor.execute("SELECT COUNT(*) FROM Asignacion WHERE id_documento = %s", (id_doc,))
    num_asignados = cursor.fetchone()[0]+1
    print("Número de asignados al documento: ", num_asignados)

    if num_asignados < 2:
        messagebox.showerror("Error", "No hay suficientes asignados para realizar la división del secreto.")
        return

    # Llamar a la función de cifrado y dividir el secreto
    ruta_archivo_cifrado= encrypt_and_split_secret(document_data,actual_path,num_asignados)
    print("Archivo cifrado en la ruta: ",ruta_archivo_cifrado)
    nuevo_hash = calcular_hash(ruta_archivo_cifrado)
    print("Nuevo hash del archivo cifrado: ",nuevo_hash)
    """Guarda el documento en la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return
    
    cursor = conexion.cursor()
    
    try:
        cursor.execute("SELECT id_documento FROM Documento WHERE ruta_archivo = %s", (actual_path,))
        resultado = cursor.fetchone()
        id_doc = resultado[0]
        print("Id del documento: ",id_doc)

        query = """
        UPDATE Documento set ruta_archivo = %s, hash = %s, estado = %s WHERE id_cliente = %s AND id_documento = %s;
        """
        cursor.execute(query, (ruta_archivo_cifrado, nuevo_hash, 'cifrado', current_user_id, id_doc))
        conexion.commit()
        print(f"Documento actualizado en la base de datos con el id_doc: {id_doc} y ruta: {ruta_archivo_cifrado}")
        messagebox.showinfo("Éxito", "Documento actualizado exitosamente.")
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al actualizar el documento: {e}")
        print(f"Error al actualizar: {e}")
    finally:
        cursor.close()
        conexion.close()

# Función para llamar a la selección de documento y continuar con el cifrado
def seleccionar_y_cifrar():
    enviar_documentos_disponibles(cifrar_doc,1)

#Funcion para creacion de pares de llaves
def guardar_llaves_en_bd_y_archivo(id_usuario):
    """Verifica el estatus de las llaves, genera nuevas si es necesario, y guarda en la base de datos y archivo."""
    try:
        # Conexión a la base de datos
        conexion = conectar_base_datos()
        if conexion is None:
            return

        cursor = conexion.cursor()

        # Verificar si el ID de usuario es válido
        if not id_usuario:
            messagebox.showerror("Error", "El ID de usuario no es válido.")
            return
        
        # Verificar si las llaves ya han sido generadas
        cursor.execute("SELECT estatus_claves FROM Usuario WHERE id_usuario = %s", (id_usuario,))
        resultado = cursor.fetchone()
        
        if resultado is None:
            messagebox.showerror("Error", f"No se encontró el usuario con ID {id_usuario}.")
            return
        
        if resultado[0] == 'generadas':  # Verificar si las llaves ya están generadas
            messagebox.showinfo("Información", "Las llaves ya han sido generadas previamente. Solicite nuevas al administrador si las necesita.")
            return
        
        # Generar llaves
        llave_privada, llave_publica = generar_llaves()
        print("Llaves privada y publica")
        print("Privada: ",llave_privada)
        print("Publica: ",llave_publica)
        # Pedir al usuario que elija dónde guardar la llave privada
        archivo_privado = filedialog.asksaveasfilename(
            title="Guardar llave privada",
            defaultextension=".pem",
            filetypes=[("Archivos PEM", "*.pem")]
        )
        
        if not archivo_privado:
            messagebox.showwarning("Cancelado", "No se seleccionó una ubicación para guardar la llave privada.")
            return
        
        # Guardar la llave privada en el archivo seleccionado
        with open(archivo_privado, "wb") as archivo:
            archivo.write(llave_privada)
        
         # Convertir la llave pública a Base64
        llave_publica_base64 = b64encode(llave_publica).decode('utf-8')

        # Guardar la llave pública en la base de datos
        cursor.execute(
            "UPDATE Usuario SET llave_publica = %s, estatus_claves = 'generadas' WHERE id_usuario = %s",
            (llave_publica_base64, id_usuario)
        )
        conexion.commit()
        
        messagebox.showinfo("Éxito", f"Llaves generadas y guardadas correctamente en:\n{archivo_privado}")
    
    except mysql.connector.Error as db_error:
        messagebox.showerror("Error de Base de Datos", f"Error al conectar o consultar la base de datos: {db_error}")
    
    except Exception as e:
        messagebox.showerror("Error", f"Error al generar o guardar las llaves: {e}")
        print(e)
    finally:
        if conexion:
            conexion.close()


#Funcion de firmado documento
def firmar_y_actualizar_documento(document_data,actual_path):
    """Función para firmar un documento, guardar la firma en un archivo y actualizar la base de datos."""
    # Solicitar al usuario el archivo a firmar
    archivo = actual_path
    if not archivo:
        messagebox.showerror("Error", "No se seleccionó ningún archivo.")
        return
    
    # Llamar a la función firma_doc para obtener la firma del documento (se asume que firma_doc regresa una tupla con (r, s))
    firma = firmar_documento(archivo)  # Asegúrate de que firma_doc esté definida en el archivo importado
    
    if not firma:
        messagebox.showerror("Error", "No se pudo generar la firma del documento.")
        return
    
    # Extraer los valores r y s (suponiendo que la firma es una tupla (r, s))
    r, s = firma
    
    # Convertir r y s a bytes y luego a Base64
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
    
    r_base64 = base64.b64encode(r_bytes).decode('utf-8')
    s_base64 = base64.b64encode(s_bytes).decode('utf-8')
    
    # Solicitar al usuario la ruta donde desea guardar el archivo de firma
    ruta_firma = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivos de texto", "*.txt")], title="Guardar Firma")
    
    if not ruta_firma:
        messagebox.showerror("Error", "No se seleccionó una ruta para guardar la firma.")
        return
    
    # Guardar la firma en el archivo seleccionado
    try:
        with open(ruta_firma, "w") as archivo_firma:
            archivo_firma.write(f"Firma (r, s) en Base64:\n")
            archivo_firma.write(f"r: {r_base64}\n")
            archivo_firma.write(f"s: {s_base64}\n")
        messagebox.showinfo("Éxito", f"Firma guardada exitosamente en: {ruta_firma}")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo guardar la firma: {e}")
        return
    
    # Conectar a la base de datos
    print("Intendando conectar a la base")
    conexion = conectar_base_datos()
    if not conexion:
            return
        
    cursor = conexion.cursor(buffered=True)
    try:
        print("Conexion realizada")
        # Obtener el id_usuario (usuario que está firmando el documento)
        id_usuario = current_user_id  # Este ID debe estar disponible desde la sesión del usuario
        
        # Buscar el id_documento basado en la ruta del archivo
        cursor.execute("SELECT id_documento FROM Documento WHERE ruta_archivo = %s", (archivo,))
        resultado = cursor.fetchone()
        
        if not resultado:
            messagebox.showerror("Error", "No se encontró el documento en la base de datos.")
            conexion.close()
            return
        
        id_documento = resultado[0]
        print("Realizado insert")
        # Insertar la firma en la tabla Firma (como Base64)
        cursor.execute("INSERT INTO Firma (id_documento, id_usuario, firma_hash) VALUES (%s, %s, %s)",
                    (id_documento, id_usuario, f"{r_base64},{s_base64}"))
        print("Realizado ")
        print("Realizando Update")
        # Actualizar el estado del documento a 'firmado'
        cursor.execute("UPDATE Documento SET estado = 'firmado_abogado' WHERE id_documento = %s", (id_documento,))
        
        conexion.commit()
        print(f"Firma generada: {r},{s}")
        # Mostrar mensaje de éxito
        messagebox.showinfo("Éxito", "Documento firmado y registrado exitosamente.")
    except mysql.connector.Error as db_error:
        messagebox.showerror("Error de Base de Datos", f"Error al conectar o consultar la base de datos: {db_error}")
        print("Error de base de datos: ",db_error)
    except Exception as e:
        messagebox.showerror("Error", f"Error al firmar el documento: {e}")
        print(e)

    finally:
        if conexion:
            conexion.close()    
    

def llamada_a_firmar():
    enviar_documentos_disponibles(firmar_y_actualizar_documento,2)

def firmar_y_actualizar_documento_cliente(document_data,actual_path):
    """Función para firmar un documento, guardar la firma en un archivo y actualizar la base de datos."""
    # Solicitar al usuario el archivo a firmar
    archivo = actual_path
    if not archivo:
        messagebox.showerror("Error", "No se seleccionó ningún archivo.")
        return
    
    # Llamar a la función firma_doc para obtener la firma del documento (se asume que firma_doc regresa una tupla con (r, s))
    firma = firmar_documento(archivo)  # Asegúrate de que firma_doc esté definida en el archivo importado
    
    if not firma:
        messagebox.showerror("Error", "No se pudo generar la firma del documento.")
        return
    
    # Extraer los valores r y s (suponiendo que la firma es una tupla (r, s))
    r, s = firma
    
    # Convertir r y s a bytes y luego a Base64
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
    
    r_base64 = base64.b64encode(r_bytes).decode('utf-8')
    s_base64 = base64.b64encode(s_bytes).decode('utf-8')
    
    # Solicitar al usuario la ruta donde desea guardar el archivo de firma
    ruta_firma = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Archivos de texto", "*.txt")], title="Guardar Firma")
    
    if not ruta_firma:
        messagebox.showerror("Error", "No se seleccionó una ruta para guardar la firma.")
        return
    
    # Guardar la firma en el archivo seleccionado
    try:
        with open(ruta_firma, "w") as archivo_firma:
            archivo_firma.write(f"Firma (r, s) en Base64:\n")
            archivo_firma.write(f"r: {r_base64}\n")
            archivo_firma.write(f"s: {s_base64}\n")
        messagebox.showinfo("Éxito", f"Firma guardada exitosamente en: {ruta_firma}")
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo guardar la firma: {e}")
        return
    
    # Conectar a la base de datos
    print("Intendando conectar a la base")
    conexion = conectar_base_datos()
    if not conexion:
            return
        
    cursor = conexion.cursor(buffered=True)
    try:
        print("Conexion realizada")
        # Obtener el id_usuario (usuario que está firmando el documento)
        id_usuario = current_user_id  # Este ID debe estar disponible desde la sesión del usuario
        
        # Buscar el id_documento basado en la ruta del archivo
        cursor.execute("SELECT id_documento FROM Documento WHERE ruta_archivo = %s", (archivo,))
        resultado = cursor.fetchone()
        
        if not resultado:
            messagebox.showerror("Error", "No se encontró el documento en la base de datos.")
            conexion.close()
            return
        
        id_documento = resultado[0]
        print("Realizado insert")
        # Insertar la firma en la tabla Firma (como Base64)
        cursor.execute("INSERT INTO Firma (id_documento, id_usuario, firma_hash) VALUES (%s, %s, %s)",
                    (id_documento, id_usuario, f"{r_base64},{s_base64}"))
        print("Realizado ")
        print("Realizando Update")
        # Actualizar el estado del documento a 'firmado'
        cursor.execute("UPDATE Documento SET estado = 'firmado_cliente' WHERE id_documento = %s", (id_documento,))
        
        conexion.commit()
        print(f"Firma generada: {r},{s}")
        # Mostrar mensaje de éxito
        messagebox.showinfo("Éxito", "Documento firmado y registrado exitosamente.")
    except mysql.connector.Error as db_error:
        messagebox.showerror("Error de Base de Datos", f"Error al conectar o consultar la base de datos: {db_error}")
        print("Error de base de datos: ",db_error)
    except Exception as e:
        messagebox.showerror("Error", f"Error al firmar el documento: {e}")
        print(e)

    finally:
        if conexion:
            conexion.close()    
    

def llamada_a_firmar_cliente():
    enviar_documentos_disponibles(firmar_y_actualizar_documento,3)

#funcion verificar firma
def obtener_usuarios_firmantes(id_documento):
    """Obtiene los usuarios que han firmado un documento."""
    conexion = conectar_base_datos()
    if not conexion:
        return []

    cursor = conexion.cursor()

    try:
        query = """
        SELECT u.id_usuario, u.nombre_completo
        FROM Usuario u
        JOIN Firma f ON u.id_usuario = f.id_usuario
        WHERE f.id_documento = %s
        """
        cursor.execute(query, (id_documento,))
        usuarios = cursor.fetchall()
        return usuarios  # Lista de tuplas (id_usuario, nombre_completo)
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al obtener usuarios firmantes: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()

def realizar_verificacion_firma(id_documento, id_usuario):
    """Realiza la verificación de la firma del usuario en el documento."""
    print(f"Realizando verificacion firma, parametros: {id_documento}, {id_usuario}")
    conexion = conectar_base_datos()
    if not conexion:
        return

    cursor = conexion.cursor()

    try:
        # Obtener firma y llave pública
        query = """
        SELECT f.firma_hash, u.llave_publica
        FROM Firma f
        JOIN Usuario u ON f.id_usuario = u.id_usuario
        WHERE f.id_documento = %s AND f.id_usuario = %s
        """
        cursor.execute(query, (id_documento, id_usuario))
        resultado = cursor.fetchone()
        print("Resultado de la consulta: ",resultado)
        cursor.execute("SELECT ruta_archivo FROM Documento WHERE id_documento = %s",(id_documento,))
        ruta_doc= cursor.fetchone()
        print("Ruta del archivo: ",ruta_doc[0])
        
        if not resultado:
            messagebox.showerror("Error", "No se encontró la firma o la llave pública.")
            return

        firma_hash, llave_publica_base64 = resultado

        llave_publica_pem = b64decode(llave_publica_base64)
         # Separar r_base64 y s_base64
        try:
            r_base64, s_base64 = firma_hash.split(",")
        except ValueError:
            messagebox.showerror("Error", "La firma almacenada tiene un formato incorrecto.")
            return

        # Decodificar r y s desde Base64 a bytes y luego a enteros
        r_bytes = base64.b64decode(r_base64)
        s_bytes = base64.b64decode(s_base64)
        r = int.from_bytes(r_bytes, byteorder='big')
        s = int.from_bytes(s_bytes, byteorder='big')
        print(f"Valores r,s: {r},{s}")
        # Verificar la firma
        if verificar_firma(ruta_doc[0],llave_publica_pem, r, s):
            messagebox.showinfo("Éxito", "La firma ha sido validada exitosamente.")
        else:
            messagebox.showerror("Error", "La firma es inválida.")
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al realizar la verificación: {e}")
    finally:
        cursor.close()
        conexion.close()
'''
def recuperar_firma_y_verificar():
    """Función para recuperar la firma desde un archivo y verificar la firma del documento."""
    # Solicitar al usuario cargar el archivo de firma
    archivo_firma = filedialog.askopenfilename(title="Seleccionar archivo de firma", filetypes=[("Archivos de texto", "*.txt")])
    
    if not archivo_firma:
        messagebox.showerror("Error", "No se seleccionó ningún archivo de firma.")
        return

    try:
        # Leer la firma desde el archivo seleccionado
        with open(archivo_firma, "r") as archivo:
            firma_base64 = archivo.readlines()
            r_base64 = firma_base64[1].split(": ")[1].strip()  # Asumiendo formato r: <base64>
            s_base64 = firma_base64[2].split(": ")[1].strip()  # Asumiendo formato s: <base64>

        # Decodificar los valores r y s desde Base64
        r_bytes = base64.b64decode(r_base64)
        s_bytes = base64.b64decode(s_base64)
        r = int.from_bytes(r_bytes, byteorder='big')
        s = int.from_bytes(s_bytes, byteorder='big')
        print(f"Valores r,s: {r},{s}")
        # Obtener la llave pública del usuario desde la base de datos
        # Se asume que current_user_id está disponible
        llave_publica_base64 = obtener_llave_publica_de_bd(current_user_id)
        print("Valor llave publica: ",llave_publica_base64)
        if not llave_publica_base64:
            messagebox.showerror("Error", "No se encontró la llave pública del usuario en la base de datos.")
            return
        print("Llave publica antes de ser eviada: ",llave_publica_base64)

        # Verificar la firma usando la función de verificación
        if verificar_firma(llave_publica_base64, r, s):
            messagebox.showinfo("Éxito", "La firma ha sido validada exitosamente.")
        else:
            messagebox.showerror("Error", "La firma es inválida.")
    
    except Exception as e:
        messagebox.showerror("Error", f"Hubo un error al verificar la firma: {e}")
        print(e)
'''

def obtener_llave_publica_de_bd(id_usuario):
    """Función para obtener la llave pública del usuario desde la base de datos."""
    # Conectar a la base de datos
    conexion = conectar_base_datos()
    if not conexion:
        return None
    
    cursor = conexion.cursor()
    
    # Consultar la llave pública del usuario
    cursor.execute("SELECT llave_publica FROM Usuario WHERE id_usuario = %s", (id_usuario,))
    resultado = cursor.fetchone()
    conexion.close()
    
    if resultado:
        # Decodificar la llave pública de Base64
        llave_publica_base64 = resultado[0]
        llave_publica_pem = b64decode(llave_publica_base64)
        return llave_publica_pem
    else:
        return None

#Funciones para asignacion de involucrados 
# Función para agregar un involucrado a la asignación de un documento
def agregar_involucrado(id_cliente, id_abogado, id_documento):
    """Agrega un involucrado a la asignación de un documento a un cliente y un abogado."""
    conexion = conectar_base_datos()
    if not conexion:
        return
    
    cursor = conexion.cursor()
    
    try:
        # Insertar la asignación en la tabla Asignacion
        query = """
        INSERT INTO Asignacion (id_cliente, id_abogado, id_documento)
        VALUES (%s, %s, %s)
        """
        cursor.execute(query, (id_cliente, id_abogado, id_documento))
        conexion.commit()
        messagebox.showinfo("Éxito", "Involucrado agregado correctamente a la asignación.")
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al agregar involucrado: {e}")
        print("Error en la base de datos: ", e)
    finally:
        cursor.close()
        conexion.close()

# Función para obtener la lista de clientes desde la base de datos
def obtener_clientes():
    """Obtiene la lista de clientes desde la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return []
    
    cursor = conexion.cursor()
    
    try:
        query = "SELECT id_usuario, nombre_completo FROM Usuario WHERE rol = 'cliente'"
        cursor.execute(query)
        clientes = cursor.fetchall()
        return clientes  # Devuelve la lista de tuplas (id_usuario, nombre_completo)
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al obtener clientes: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()

# Función para obtener la lista de abogados desde la base de datos
def obtener_abogados():
    """Obtiene la lista de abogados desde la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return []
    
    cursor = conexion.cursor()
    
    try:
        cursor.execute("SELECT id_usuario, nombre_completo FROM Usuario WHERE rol = 'abogado'")
        abogados = cursor.fetchall()
        return abogados  # Devuelve la lista de tuplas (id_usuario, nombre_completo)
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al obtener abogados: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()

# Función para obtener la lista de documentos disponibles desde la base de datos
def obtener_documentos():
    """Obtiene la lista de documentos disponibles desde la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return []
    
    cursor = conexion.cursor()
    
    try:
        query = "SELECT id_documento, ruta_archivo FROM Documento WHERE id_cliente = %s"
        cursor.execute(query, (current_user_id,))
        documentos = cursor.fetchall()
        return documentos  # Devuelve la lista de tuplas (id_documento, ruta_archivo)
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al obtener documentos: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()


def obtener_documentos_firmados():
    """Obtiene los documentos firmados asociados al usuario actual."""
    conexion = conectar_base_datos()
    if not conexion:
        return []

    cursor = conexion.cursor()

    try:
        query = """
        SELECT DISTINCT d.id_documento, d.ruta_archivo
        FROM Documento d
        JOIN Firma f ON d.id_documento = f.id_documento
        JOIN Asignacion a ON d.id_documento = a.id_documento
        WHERE a.id_abogado = %s OR a.id_cliente = %s
        """
        cursor.execute(query, (current_user_id, current_user_id))
        documentos = cursor.fetchall()
        return documentos  # Lista de tuplas (id_documento, ruta_archivo)
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al obtener documentos firmados: {e}")
        return []
    finally:
        cursor.close()
        conexion.close()
# Pantalla principal para cliente
def show_client_screen():
    clear_screen()
    tk.Label(root, text="Bienvenido, Cliente", font=("Arial", 16)).pack(pady=10)
    tk.Button(root, text="Generar Par de Llaves", command=lambda: guardar_llaves_en_bd_y_archivo(current_user_id)).pack(pady=5)
    tk.Button(root, text="Firmar documento", command=llamada_a_firmar_cliente).pack(pady=5)
    tk.Button(root, text="Verificar Firma", command=verificar_firma_documento).pack(pady=5)
    tk.Button(root, text="Cerrar Sesión", command=mostrar_pantalla_bienvenida).pack(pady=10)

# Pantalla principal para abogado
def show_lawyer_screen():
    clear_screen()
    tk.Label(root, text="Bienvenido, Abogado", font=("Arial", 16)).pack(pady=10)
    # Botón para cifrar documento
    tk.Button(root, text="Cargar Documento", command=cargar_documento).pack(pady=5)
    tk.Button(root, text="Generar Par de Llaves", command=lambda: guardar_llaves_en_bd_y_archivo(current_user_id)).pack(pady=5)
    tk.Button(root, text="Agregar Involucrado", command=mostrar_formulario_asignacion).pack(pady=5)
    tk.Button(root, text="Cifrar Documento", command=seleccionar_y_cifrar).pack(pady=5)
    tk.Button(root, text="Firmar Documento", command=llamada_a_firmar).pack(pady=5)
    tk.Button(root, text="Verificar Firma", command=verificar_firma_documento).pack(pady=5)
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


# Función para mostrar el formulario de asignación
def mostrar_formulario_asignacion():
    """Muestra el formulario para agregar un involucrado a la asignación de un documento."""
    clear_screen()
    tk.Label(root, text="Asignar Documento a Involucrado", font=("Arial", 16)).pack(pady=10)
    
    # Seleccionar cliente
    tk.Label(root, text="Seleccionar Cliente").pack(pady=5)
    clientes = obtener_clientes()  # Función que obtiene los clientes de la base de datos
    cliente_var = tk.StringVar()
    cliente_menu = tk.OptionMenu(root, cliente_var, *[cliente[1] for cliente in clientes])  # Mostrar solo los nombres
    cliente_menu.pack(pady=5)
    
    # Seleccionar abogado
    tk.Label(root, text="Seleccionar Abogado").pack(pady=5)
    abogados = obtener_abogados()  # Función que obtiene los abogados de la base de datos
    abogado_var = tk.StringVar()
    abogado_menu = tk.OptionMenu(root, abogado_var, *[abogado[1] for abogado in abogados])  # Mostrar solo los nombres
    abogado_menu.pack(pady=5)
    
    # Seleccionar documento
    tk.Label(root, text="Seleccionar Documento").pack(pady=5)
    documentos = obtener_documentos()  # Función que obtiene los documentos disponibles
    documento_var = tk.StringVar()
    documento_menu = tk.OptionMenu(root, documento_var, *[documento[1] for documento in documentos])  # Mostrar solo las rutas
    documento_menu.pack(pady=5)
    
    # Botón para agregar la asignación
    tk.Button(root, text="Asignar", command=lambda: agregar_involucrado(
        next(cliente[0] for cliente in clientes if cliente[1] == cliente_var.get()),  # Obtener id_usuario del cliente
        next(abogado[0] for abogado in abogados if abogado[1] == abogado_var.get()),  # Obtener id_usuario del abogado
        next(documento[0] for documento in documentos if documento[1] == documento_var.get())  # Obtener id_documento
    )).pack(pady=10)
    
    tk.Button(root, text="Regresar", command=show_lawyer_screen).pack(pady=10)

#Funcion para la verificacion de firma
def verificar_firma_documento():
    """Permite seleccionar un documento firmado, elegir un usuario y verificar su firma."""
    clear_screen()
    tk.Label(root, text="Verificar Firma de Documento", font=("Arial", 16)).pack(pady=10)

    # Obtener documentos firmados asociados al usuario actual
    documentos = obtener_documentos_firmados()  # Función que obtiene documentos firmados de la base de datos
    
    if documentos:
        # Seleccionar documento
        tk.Label(root, text="Seleccionar Documento").pack(pady=5)
        documento_var = tk.StringVar(value=f"{documentos[0][0]} - {documentos[0][1]}")  # Inicializar con el primer documento
        documento_menu = tk.OptionMenu(root, documento_var, *[f"{doc[0]} - {doc[1]}" for doc in documentos])
        documento_menu.pack(pady=5)
    else:
        # Manejar el caso en que no haya documentos firmados
        tk.Label(root, text="No hay documentos firmados disponibles.").pack(pady=10)
        tk.Button(root, text="Regresar", command=show_lawyer_screen).pack(pady=10)
        return

    # Obtener usuarios que han firmado el documento seleccionado
    tk.Label(root, text="Seleccionar Usuario Firmante").pack(pady=5)
    usuarios_firmantes = obtener_usuarios_firmantes(documentos[0][0])  # Obtener usuarios del primer documento como ejemplo
    
    if usuarios_firmantes:
        usuario_var = tk.StringVar(value=f"{usuarios_firmantes[0][0]} - {usuarios_firmantes[0][1]}")  # Inicializar con el primer usuario
        usuario_menu = tk.OptionMenu(root, usuario_var, *[f"{usr[0]} - {usr[1]}" for usr in usuarios_firmantes])
        usuario_menu.pack(pady=5)
    else:
        # Manejar el caso en que no haya usuarios firmantes
        tk.Label(root, text="No hay usuarios firmantes para este documento.").pack(pady=10)
        tk.Button(root, text="Regresar", command=show_lawyer_screen).pack(pady=10)
        return
    # Botón para verificar la firma
    tk.Button(root, text="Verificar Firma", command=lambda: realizar_verificacion_firma(
        documento_var.get().split(" - ")[0],  # Obtener ID del documento seleccionado
        usuario_var.get().split(" - ")[0]  # Obtener ID del usuario seleccionado
    )).pack(pady=10)

    tk.Button(root, text="Regresar", command=regresar_a_pantalla).pack(pady=10)

def regresar_a_pantalla():
    """Regresa a la pantalla principal adecuada según el tipo de usuario."""
    if current_user_type == "cliente":
        show_client_screen()
    elif current_user_type == "abogado":
        show_lawyer_screen()
    else:
        messagebox.showerror("Error", "Tipo de usuario no definido.")

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
