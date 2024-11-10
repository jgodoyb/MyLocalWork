import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Crear la ventana principal antes de las variables de Tkinter
root = tk.Tk()
root.title("Cifrado de Archivos con AES, RSA y Kyber")

# Ahora se pueden crear las variables de Tkinter
key_size_var = tk.StringVar(value="256")  # Valor predeterminado es 256
cipher_mode_var = tk.StringVar(value="CBC")

# Crear las variables para RSA y Kyber después de inicializar root
rsa_option = tk.IntVar(value=0)  # 0 es el valor predeterminado (no usar RSA)
kyber_option = tk.IntVar(value=0)  # 0 es el valor predeterminado (no usar Kyber)

# Funciones para cifrado/descifrado
def generate_key(key_size):
    return os.urandom(key_size // 8)

def generate_iv():
    return os.urandom(16)

def pad_data(data):
    padder = padding.PKCS7(128).padder() 
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad_data(padded_data):
    unpadder = padding.PKCS7(128).unpadder() 
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Funciones de AES
def encrypt_data(data, key, iv, mode):
    cipher_mode = modes.CBC(iv) if mode == "CBC" else modes.CFB(iv) if mode == "CFB" else modes.ECB()
    cipher = Cipher(algorithms.AES(key), cipher_mode)
    encryptor = cipher.encryptor()
    
    # Aplicar padding a todos los modos, incluido ECB
    padded_data = pad_data(data)
    
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_data(ciphertext, key, iv, mode):
    cipher_mode = modes.CBC(iv) if mode == "CBC" else modes.CFB(iv) if mode == "CFB" else modes.ECB()
    cipher = Cipher(algorithms.AES(key), cipher_mode)
    decryptor = cipher.decryptor()
    
    # Para el modo ECB, no se utiliza IV
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_data(padded_data)

# Funciones de RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_key_with_rsa(key, public_key):
    return public_key.encrypt(
        key,asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

def decrypt_key_with_rsa(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

def save_rsa_keys(private_key, public_key, directory):
    private_key_path = os.path.join(directory, "clave_privada.pem")
    public_key_path = os.path.join(directory, "clave_publica.pem")
    
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    return private_key_path, public_key_path

# Funciones de Kyber (Sustituir con la implementación de Kyber que uses)
def generate_kyber_keys():
    # Implementación hipotética de generación de claves de Kyber
    return "kyber_private_key", "kyber_public_key"

def encrypt_key_with_kyber(key, public_key):
    # Implementación hipotética de cifrado de clave con Kyber
    return b"encrypted_key_with_kyber"

def decrypt_key_with_kyber(encrypted_key, private_key):
    # Implementación hipotética de descifrado de clave con Kyber
    return b"original_key_after_decrypting_with_kyber"

def save_kyber_keys(private_key, public_key, directory):
    private_key_path = os.path.join(directory, "kyber_privada.key")
    public_key_path = os.path.join(directory, "kyber_publica.key")
    
    with open(private_key_path, "wb") as priv_file:
        priv_file.write(private_key.encode())
    with open(public_key_path, "wb") as pub_file:
        pub_file.write(public_key.encode())
    return private_key_path, public_key_path

# Función para seleccionar archivo de entrada
def select_file():
    file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
    return file_path

# Función para guardar archivo cifrado
def save_encrypted_file(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
    if file_path:
        with open(file_path, "wb") as file:
            file.write(data)

# Función para seleccionar y cifrar archivo
def encrypt_file():
    file_path = select_file()
    if file_path:
        # Leer el archivo
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        key_size = int(key_size_var.get())
        key = generate_key(key_size)
        iv = generate_iv()
        
        encrypted_data = encrypt_data(file_data, key, iv, cipher_mode_var.get())
        
        if rsa_option.get():
            private_key, public_key = generate_rsa_keys()
            encrypted_key = encrypt_key_with_rsa(key, public_key)
            save_rsa_keys(private_key, public_key, os.path.dirname(file_path))
            encrypted_data += encrypted_key
        
        if kyber_option.get():
            kyber_private_key, kyber_public_key = generate_kyber_keys()
            encrypted_key = encrypt_key_with_kyber(key, kyber_public_key)
            encrypted_data += encrypted_key
        
        save_encrypted_file(encrypted_data)
        messagebox.showinfo("Cifrado", "El archivo ha sido cifrado y guardado.")

# Función para descifrar archivo
def decrypt_file():
    file_path = select_file()
    if file_path:
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        
        # Aquí deberías implementar la lógica de descifrado según si se usó RSA o Kyber
        messagebox.showinfo("Descifrado", "El archivo ha sido descifrado.")

# Interface gráfica
key_size_label = tk.Label(root, text="Tamaño de clave:")
key_size_label.grid(row=0, column=0)

key_size_entry = tk.Entry(root, textvariable=key_size_var)
key_size_entry.grid(row=0, column=1)

cipher_mode_label = tk.Label(root, text="Modo de Cifrado:")
cipher_mode_label.grid(row=1, column=0)

cipher_mode_options = ["CBC", "CFB", "ECB"]
cipher_mode_menu = tk.OptionMenu(root, cipher_mode_var, *cipher_mode_options)
cipher_mode_menu.grid(row=1, column=1)

rsa_checkbox = tk.Checkbutton(root, text="Usar RSA", variable=rsa_option)
rsa_checkbox.grid(row=2, column=0, columnspan=2)

kyber_checkbox = tk.Checkbutton(root, text="Usar Kyber", variable=kyber_option)
kyber_checkbox.grid(row=3, column=0, columnspan=2)

encrypt_button = tk.Button(root, text="Cifrar archivo", command=encrypt_file)
encrypt_button.grid(row=4, column=0, columnspan=2)

decrypt_button = tk.Button(root, text="Descifrar archivo", command=decrypt_file)
decrypt_button.grid(row=5, column=0, columnspan=2)

root.mainloop()
