import mysql.connector
import json
import hashlib
import os
from getpass import getpass
import sys
import tkinter as tk
from tkinter import messagebox

#CONEXIÓN CON LA BASE DE DATOS
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

#REGISTRO DE USUARIO 
def registrar_usuario(nombre_usuario, contraseña, confirmar_contraseña, rol, nombre_completo):
    """Registra un usuario en la base de datos."""
    if contraseña != confirmar_contraseña:
        messagebox.showerror("Error", "Las contraseñas no coinciden. Intente nuevamente.")
        return
    
    if rol not in ['cliente', 'abogado', 'administrador']:
        messagebox.showerror("Error", "Rol no válido. Debe ser 'cliente', 'abogado' o 'administrador'.")
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
    except mysql.connector.Error as e:
        messagebox.showerror("Error", f"Error al registrar el usuario: {e}")
    finally:
        cursor.close()
        conexion.close()

#INICIAR SESIÓN
def iniciar_sesion(nombre_usuario, contraseña):
    """Inicia sesión de un usuario en la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return False
    
    cursor = conexion.cursor(dictionary=True)
    
    try:
        query = "SELECT * FROM Usuario WHERE nombre_usuario = %s"
        cursor.execute(query, (nombre_usuario,))
        usuario = cursor.fetchone()
        if usuario and hashear_contraseña(contraseña) == usuario['contraseña_hash']:
            messagebox.showinfo("Éxito", "Inicio de sesión exitoso.")
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

def interfaz_principal():
    # Declaracion inicial de interfaz
    root = tk.Tk()
    root.title("Sistema de Firma y Cifrado de Documentos")
    root.geometry("400x300")

    def mostrar_registro():
        registro_ventana = tk.Toplevel(root)
        registro_ventana.title("Registro de Usuario")

        tk.Label(registro_ventana, text="Nombre de usuario:").grid(row=0, column=0, padx=10, pady=5)
        tk.Label(registro_ventana, text="Contraseña:").grid(row=1, column=0, padx=10, pady=5)
        tk.Label(registro_ventana, text="Confirmar Contraseña:").grid(row=2, column=0, padx=10, pady=5)
        tk.Label(registro_ventana, text="Rol:").grid(row=3, column=0, padx=10, pady=5)
        tk.Label(registro_ventana, text="Nombre Completo:").grid(row=4, column=0, padx=10, pady=5)

        nombre_usuario_entry = tk.Entry(registro_ventana)
        contraseña_entry = tk.Entry(registro_ventana, show="*")
        confirmar_contraseña_entry = tk.Entry(registro_ventana, show="*")
        rol_entry = tk.Entry(registro_ventana)
        nombre_completo_entry = tk.Entry(registro_ventana)

        nombre_usuario_entry.grid(row=0, column=1, padx=10, pady=5)
        contraseña_entry.grid(row=1, column=1, padx=10, pady=5)
        confirmar_contraseña_entry.grid(row=2, column=1, padx=10, pady=5)
        rol_entry.grid(row=3, column=1, padx=10, pady=5)
        nombre_completo_entry.grid(row=4, column=1, padx=10, pady=5)

        tk.Button(registro_ventana, text="Registrar", command=lambda: registrar_usuario(
            nombre_usuario_entry.get(),
            contraseña_entry.get(),
            confirmar_contraseña_entry.get(),
            rol_entry.get(),
            nombre_completo_entry.get()
        )).grid(row=5, column=0, columnspan=2, pady=10)

    def mostrar_inicio_sesion():
        inicio_sesion_ventana = tk.Toplevel(root)
        inicio_sesion_ventana.title("Inicio de Sesión")

        tk.Label(inicio_sesion_ventana, text="Nombre de usuario:").grid(row=0, column=0, padx=10, pady=5)
        tk.Label(inicio_sesion_ventana, text="Contraseña:").grid(row=1, column=0, padx=10, pady=5)

        nombre_usuario_entry = tk.Entry(inicio_sesion_ventana)
        contraseña_entry = tk.Entry(inicio_sesion_ventana, show="*")

        nombre_usuario_entry.grid(row=0, column=1, padx=10, pady=5)
        contraseña_entry.grid(row=1, column=1, padx=10, pady=5)

        tk.Button(inicio_sesion_ventana, text="Iniciar Sesión", command=lambda: iniciar_sesion(
            nombre_usuario_entry.get(),
            contraseña_entry.get()
        )).grid(row=2, column=0, columnspan=2, pady=10)

    tk.Button(root, text="Registro de Usuario", command=mostrar_registro).pack(pady=20)
    tk.Button(root, text="Inicio de Sesión", command=mostrar_inicio_sesion).pack(pady=20)

    root.mainloop()

if __name__ == "__main__":
    interfaz_principal()
