import tkinter as tk
from tkinter import messagebox

# Función login
def login():
    user = user_entry.get()
    password = pass_entry.get()
    
    if user == "cliente":  #Temporal para iniciar como cliente
        show_client_screen()
    elif user == "abogado":  #Temporal para inciar como abogado
        show_lawyer_screen()
    else:
        messagebox.showerror("Error", "Usuario o contraseña incorrectos")

# Pantalla principal para cliente
def show_client_screen():
    clear_screen()
    tk.Label(root, text="Bienvenido, Cliente", font=("Arial", 16)).pack(pady=10)
    tk.Button(root, text="Generar Par de Llaves", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Compartir Secreto", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Cerrar Sesión", command=show_login_screen).pack(pady=10)

# Pantalla principal para abogado
def show_lawyer_screen():
    clear_screen()
    tk.Label(root, text="Bienvenido, Abogado", font=("Arial", 16)).pack(pady=10)
    tk.Button(root, text="Generar Par de Llaves", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Firmar Documento", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Cifrar Documento", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Visualizar Documento", command=lambda: None).pack(pady=5)
    tk.Button(root, text="Cerrar Sesión", command=show_login_screen).pack(pady=10)

# Pantalla de login
def show_login_screen():
    clear_screen()
    tk.Label(root, text="Inicio de Sesión", font=("Arial", 16)).pack(pady=10)
    global user_entry, pass_entry
    tk.Label(root, text="Usuario").pack(pady=5)
    user_entry = tk.Entry(root)
    user_entry.pack(pady=5)
    tk.Label(root, text="Contraseña").pack(pady=5)
    pass_entry = tk.Entry(root, show="*")
    pass_entry.pack(pady=5)
    tk.Button(root, text="Iniciar Sesión", command=login).pack(pady=10)

# Función para eliminar pantalla anterior
def clear_screen():
    for widget in root.winfo_children():
        widget.destroy()

# Declaracion inicial de interfaz
root = tk.Tk()
root.title("Sistema de Firma y Cifrado de Documentos")
root.geometry("400x300")

# Mostrar la pantalla de login de inicio
show_login_screen()

# Ejecución de la aplicación
root.mainloop()
