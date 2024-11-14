import os
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

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

# Formula de RSA --> c = m^e (mod n)
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

def load_and_encrypt_any_file():
    filepath = filedialog.askopenfilename(title="Selecciona el archivo que deseea encriptar",filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("PDF files", "*.pdf"), ("Images", "*.png")])
    if filepath:
        if filepath.endswith('.txt'):
            with open(filepath, 'r', encoding='utf-8') as file:
                content = file.read().encode('utf-8')
        else:
            with open(filepath, 'rb') as file:
                content = file.read()
        
        encrypt_loaded_file(filepath, content)

def encrypt_loaded_file(filepath, content):
    try:
        key_size = int(key_size_var.get())
        mode = cipher_mode_var.get()

        key = generate_key(key_size)
        iv = generate_iv() if mode != "ECB" else b''
        ciphertext = encrypt_data(content, key, iv, mode)

        with open(filepath, 'wb') as file:
            file.write(iv + ciphertext)

        if rsa_option.get() == 1:
            # El usuario debe seleccionar la clave pública RSA
            public_key_path = filedialog.askopenfilename(title="Selecciona la clave pública RSA", filetypes=[("PEM files", "*.pem")])
            if not public_key_path:
                messagebox.showerror("Error", "Por favor, selecciona la clave pública RSA.")
                return
            
            with open(public_key_path, "rb") as public_file:
                public_key = serialization.load_pem_public_key(
                    public_file.read(),
                    backend=default_backend()
                )
            encrypted_key = encrypt_key_with_rsa(key, public_key)
            key_filepath = filepath + '_key_rsa.bin'
            with open(key_filepath, 'wb') as key_file:
                key_file.write(encrypted_key)

            messagebox.showinfo("Éxito", f"Archivo cifrado guardado en {filepath}.\n"
                                         f"Clave AES cifrada guardada en {key_filepath}.\n"
                                         f"Clave pública RSA utilizada: {public_key_path}")
        else:
            key_filepath = filepath + '.txt'
            with open(key_filepath, 'w') as key_file:
                key_file.write(key.hex())

            messagebox.showinfo("Éxito", f"Archivo cifrado guardado en {filepath}.\nClave guardada en {key_filepath}.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_action():
    try:
        filepath = filedialog.askopenfilename(title="Selecciona el archivo encriptado", filetypes=[("All files", "*.*"), ("Encrypted files", "*.enc"), ("Text files", "*.txt"), ("PDF files", "*.pdf"), ("Images", "*.png")])
        if filepath:
            with open(filepath, 'rb') as file:
                data = file.read()

            mode = cipher_mode_var.get()
            iv = data[:16] if mode != "ECB" else b'' 
            ciphertext = data[16:] if mode != "ECB" else data

            key_filepath = filedialog.askopenfilename(title="Selecciona la clave secreta cifrada",filetypes=[("Key files", "*.bin;*.txt")])
            if not key_filepath:
                messagebox.showerror("Error", "Por favor, selecciona el archivo de clave.")
                return

            if key_filepath.endswith('_key_rsa.bin'):
                private_key_path = filedialog.askopenfilename(title="Selecciona la clave privada RSA", filetypes=[("PEM files", "*.pem")])
                if not private_key_path:
                    messagebox.showerror("Error", "Por favor, selecciona la clave privada RSA.")
                    return
                
                with open(private_key_path, "rb") as private_file:
                    private_key = serialization.load_pem_private_key(
                        private_file.read(),
                        password=None,
                        backend=default_backend()
                    )
                with open(key_filepath, 'rb') as key_file:
                    encrypted_key = key_file.read()
                key = decrypt_key_with_rsa(encrypted_key, private_key)
            else:
                with open(key_filepath, 'r') as key_file:
                    key = bytes.fromhex(key_file.read())

            plaintext = decrypt_data(ciphertext, key, iv, mode)

            with open(filepath, 'wb') as output_file:
                output_file.write(plaintext)

            messagebox.showinfo("Éxito", f"Archivo descifrado y actualizado en {filepath}.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def encrypt_text():
    try:
        text = text_input.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showwarning("Advertencia", "El texto está vacío.")
            return

        key_size = int(key_size_var.get())
        mode = cipher_mode_var.get()

        key = generate_key(key_size)
        iv = generate_iv() if mode != "ECB" else b'' 
        ciphertext = encrypt_data(text.encode('utf-8'), key, iv, mode)

        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Encrypted files", "*.txt")])
        if save_path:
            with open(save_path, 'wb') as file:
                file.write(iv + ciphertext)

            if rsa_option.get() == 1:
                # El usuario debe seleccionar la clave pública RSA
                public_key_path = filedialog.askopenfilename(title="Selecciona la clave pública RSA", filetypes=[("PEM files", "*.pem")])
                if not public_key_path:
                    messagebox.showerror("Error", "Por favor, selecciona la clave pública RSA.")
                    return

                with open(public_key_path, "rb") as public_file:
                    public_key = serialization.load_pem_public_key(public_file.read(), backend=default_backend())
                encrypted_key = encrypt_key_with_rsa(key, public_key)

                key_filepath = save_path + '_key_rsa.bin'
                with open(key_filepath, 'wb') as key_file:
                    key_file.write(encrypted_key)

                messagebox.showinfo("Éxito", f"Texto cifrado guardado en {save_path}.\nClave AES cifrada guardada en {key_filepath}.\nClave pública RSA utilizada: {public_key_path}")
            else:
                key_filepath = save_path + '.txt'
                with open(key_filepath, 'w') as key_file:
                    key_file.write(key.hex())

                messagebox.showinfo("Éxito", f"Texto cifrado guardado en {save_path}.\nClave guardada en {key_filepath}.")
        else:
            messagebox.showwarning("Advertencia", "No se seleccionó ningún archivo para guardar el texto cifrado.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def generate_rsa_keys_action():
    save_path = filedialog.askdirectory()
    if save_path:
        private_key, public_key = generate_rsa_keys()
        private_key_path, public_key_path = save_rsa_keys(private_key, public_key, save_path)
        messagebox.showinfo("Éxito", f"Claves RSA generadas y guardadas en {save_path}\n"
                                    f"Clave privada: {private_key_path}\nClave pública: {public_key_path}")

# Interfaz gráfica de Tkinter
root = tk.Tk()
root.title("Cifrado de Archivos con AES y RSA")
root.geometry("500x400")
root.config(bg="#f0f0f0")

# Variable de selección para el tamaño de clave y el modo de cifrado
key_size_var = tk.StringVar(value="256")
cipher_mode_var = tk.StringVar(value="CBC")
rsa_option = tk.IntVar(value=0)

# Estilo
style = ttk.Style()
style.configure("TLabel", font=("Arial", 10), background="#f0f0f0")
style.configure("TButton", font=("Arial", 10), padding=5)
style.configure("TCheckbutton", font=("Arial", 10), background="#f0f0f0")
style.configure("TOptionMenu", font=("Arial", 10))

# Etiquetas y opciones de tamaño de clave
key_size_label = ttk.Label(root, text="Tamaño de la clave AES:")
key_size_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

key_size_options = ["128", "192", "256"]
key_size_menu = ttk.OptionMenu(root, key_size_var, *key_size_options)
key_size_menu.grid(row=0, column=1, padx=10, pady=10, sticky="w")

# Etiquetas y opciones de modo de cifrado
cipher_mode_label = ttk.Label(root, text="Modo de cifrado:")
cipher_mode_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

cipher_mode_options = ["CBC", "CFB", "ECB"]
cipher_mode_menu = ttk.OptionMenu(root, cipher_mode_var, *cipher_mode_options)
cipher_mode_menu.grid(row=1, column=1, padx=10, pady=10, sticky="w")

# Checkbox para RSA
rsa_checkbox = ttk.Checkbutton(root, text="Usar RSA para cifrar la clave AES", variable=rsa_option)
rsa_checkbox.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="w")

# Botón para generar claves RSA
generate_rsa_button = ttk.Button(root, text="Generar claves RSA", command=generate_rsa_keys_action)
generate_rsa_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

# Botones de cifrado y descifrado de archivo
encrypt_button = ttk.Button(root, text="Cifrar Archivo", command=load_and_encrypt_any_file)
encrypt_button.grid(row=4, column=0, padx=10, pady=10)

decrypt_button = ttk.Button(root, text="Descifrar Archivo", command=decrypt_action)
decrypt_button.grid(row=4, column=1, padx=10, pady=10)

# Texto y botón para cifrar texto
text_input_label = ttk.Label(root, text="Texto a cifrar:")
text_input_label.grid(row=5, column=0, padx=10, pady=10, sticky="w")

text_input = tk.Text(root, height=4, width=40, font=("Arial", 10))
text_input.grid(row=5, column=1, padx=10, pady=10, sticky="w")

encrypt_text_button = ttk.Button(root, text="Cifrar Texto", command=encrypt_text)
encrypt_text_button.grid(row=6, column=0, columnspan=2, pady=10)

# Ejecutar el bucle principal de la ventana
root.mainloop()
