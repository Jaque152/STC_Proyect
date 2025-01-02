import mysql.connector
import json
from getpass import getpass
import hashlib
import os

def cargar_configuracion():
    """Carga la configuración de la base de datos desde un archivo JSON."""
    try:
        ruta_config = os.path.join("config", "db_config.json")
        with open(ruta_config, "r") as archivo:
            config = json.load(archivo)
        return config
    except FileNotFoundError:
        print("Error: No se encontró el archivo de configuración 'db_config.json'.")
        return None
    except json.JSONDecodeError:
        print("Error: El archivo de configuración no tiene un formato JSON válido.")
        return None

def conectar_base_datos():
    """Establece la conexión con la base de datos usando la configuración cargada."""
    db_config = cargar_configuracion()
    if not db_config:
        return None
    try:
        conexion = mysql.connector.connect(**db_config)
        return conexion
    except mysql.connector.Error as e:
        print(f"Error al conectar con la base de datos: {e}")
        return None

def hashear_contraseña(contraseña):
    """Hashea la contraseña usando SHA-256."""
    sha256 = hashlib.sha256()
    sha256.update(contraseña.encode('utf-8'))
    return sha256.hexdigest()

def registrar_usuario():
    """Registra un usuario en la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return
    
    cursor = conexion.cursor()
    
    print("\n--- Registro de Usuario ---")
    nombre_usuario = input("Nombre de usuario (único): ").strip()
    contraseña = getpass("Contraseña: ").strip()
    confirmar_contraseña = getpass("Confirmar contraseña: ").strip()
    
    if contraseña != confirmar_contraseña:
        print("Las contraseñas no coinciden. Intente nuevamente.")
        return
    
    rol = input("Rol (cliente/abogado): ").strip().lower()
    if rol not in ['cliente', 'abogado']:
        print("Rol no válido. Debe ser 'cliente' o 'abogado'.")
        return
    
    nombre_completo = input("Nombre completo: ").strip()
    
    # Hashear la contraseña
    contraseña_hash = hashear_contraseña(contraseña)
    
    try:
        query = """
        INSERT INTO Usuario (nombre_usuario, contraseña_hash, rol, nombre_completo)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (nombre_usuario, contraseña_hash, rol, nombre_completo))
        conexion.commit()
        print(f"Usuario '{nombre_usuario}' registrado exitosamente.")
    except mysql.connector.Error as e:
        print(f"Error al registrar el usuario: {e}")
    finally:
        cursor.close()
        conexion.close()

def verificar_usuario(nombre_usuario):
    """Verifica si un usuario existe en la base de datos."""
    conexion = conectar_base_datos()
    if not conexion:
        return False
    
    cursor = conexion.cursor(dictionary=True)
    
    try:
        query = "SELECT * FROM Usuario WHERE nombre_usuario = %s"
        cursor.execute(query, (nombre_usuario,))
        usuario = cursor.fetchone()
        if usuario:
            print("\nUsuario encontrado:")
            print(f"ID: {usuario['id_usuario']}")
            print(f"Nombre de usuario: {usuario['nombre_usuario']}")
            print(f"Rol: {usuario['rol']}")
            print(f"Nombre completo: {usuario['nombre_completo']}")
            return True
        else:
            print("\nNo se encontró el usuario.")
            return False
    except mysql.connector.Error as e:
        print(f"Error al consultar el usuario: {e}")
        return False
    finally:
        cursor.close()
        conexion.close()

if __name__ == "__main__":
    while True:
        print("\nOpciones:")
        print("1. Registrar usuario")
        print("2. Verificar usuario")
        print("3. Salir")
        opcion = input("Seleccione una opción: ").strip()
        
        if opcion == "1":
            registrar_usuario()
        elif opcion == "2":
            nombre_usuario = input("Ingrese el nombre de usuario a buscar: ").strip()
            verificar_usuario(nombre_usuario)
        elif opcion == "3":
            print("Saliendo del programa.")
            break
        else:
            print("Opción no válida. Intente nuevamente.")
