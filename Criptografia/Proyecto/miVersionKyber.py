import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives import (padding, serialization, hashes)
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256 
from cryptography.hazmat.primitives import hashes 
import hashlib
import json
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
from cryptography.hazmat.primitives import padding



# ------------------------------------ Generación de Claves y Componentes Criptográficos ------------------------------------ # 




# Genera una clave aleatoria de un tamaño específico en bits.
def generate_key(key_size):
    return os.urandom(key_size // 8)

# Genera un vector de inicialización (IV) aleatorio de 16 bytes.
def generate_iv():
    return os.urandom(16)

# Genera un par de claves RSA (privada y pública) con un tamaño de 2048 bits.
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key



# ------------------------------------ Gestión de Claves RSA ------------------------------------ # 




# Guarda las claves RSA generadas en el directorio especificado.
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

# Cifra una clave utilizando RSA con la clave pública proporcionada.
def encrypt_key_with_rsa(key, public_key):
    return public_key.encrypt(
        key,asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )

# Descifra una clave cifrada con RSA utilizando la clave privada proporcionada.
def decrypt_key_with_rsa(encrypted_key, private_key):
    return private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )




# ------------------------------------ Padding  ------------------------------------ # 




# Aplica un padding PKCS7 al dato de entrada para que sea múltiplo de 16 bytes.
def pad_data(data):
    padder = padding.PKCS7(128).padder() 
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Elimina el padding PKCS7 de los datos de entrada.
def unpad_data(padded_data):
    unpadder = padding.PKCS7(128).unpadder() 
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data




# ------------------------------------ Cifrado y Descifrado de Datos con AES  ------------------------------------ # 




# Cifra los datos con el algoritmo AES utilizando un modo de operación específico (CBC, CFB, ECB).
def encrypt_data(data, key, iv, mode):
    cipher_mode = modes.CBC(iv) if mode == "CBC" else modes.CFB(iv) if mode == "CFB" else modes.ECB()
    cipher = Cipher(algorithms.AES(key), cipher_mode)
    encryptor = cipher.encryptor()
    
    # Aplicar padding a todos los modos, incluido ECB
    padded_data = pad_data(data)
    
    return encryptor.update(padded_data) + encryptor.finalize()

# Descifra los datos cifrados con AES utilizando un modo de operación específico.
def decrypt_data(ciphertext, key, iv, mode):
    cipher_mode = modes.CBC(iv) if mode == "CBC" else modes.CFB(iv) if mode == "CFB" else modes.ECB()
    cipher = Cipher(algorithms.AES(key), cipher_mode)
    decryptor = cipher.decryptor()
    
    # Para el modo ECB, no se utiliza IV
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_data(padded_data)




# ------------------------------------ Cifrado y Descifrado de Archivos y Texto ------------------------------------ # 




# Cifrado de Archivos con Múltiples Usuarios y Cabecera Personalizada
def encrypt_with_selected_users():
    """Cifra un archivo seleccionando múltiples usuarios o solo para el usuario que cifra."""
    try:
        global loaded_public_key, loaded_username

        # Verificar el certificado del usuario que está cifrando
        if not verificar_certificado_usuario(loaded_username):
            messagebox.showerror(
                "Error de Certificado", 
                f"El certificado del usuario '{loaded_username}' no es válido. Operación cancelada."
            )
            return  # Detener la operación si el certificado no es válido

        # Seleccionar archivo para cifrar
        filepath = filedialog.askopenfilename(
            title="Selecciona el archivo que desea cifrar",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("PDF files", "*.pdf"), ("Images", "*.png")]
        )
        if not filepath:
            return

        # Leer contenido del archivo
        with open(filepath, 'rb') as file:
            content = file.read()

        # Seleccionar usuarios adicionales de la lista
        selected_indices = user_list.curselection()
        selected_users = [user_list.get(i) for i in selected_indices]

        # Verificar si no se seleccionaron usuarios adicionales
        if not selected_users:
            messagebox.showinfo(
                "Información",
                "No seleccionaste usuarios adicionales. El archivo será cifrado solo para ti."
            )
        
        # Generar clave AES y cifrar contenido
        key_size = int(key_size_var.get())
        key = generate_key(key_size)
        iv = generate_iv()
        mode = cipher_mode_var.get()
        ciphertext = encrypt_data(content, key, iv, mode)

        # Construir cabecera
        header = []

        # Si hay usuarios adicionales seleccionados, procesarlos
        for user in selected_users:
            user_dir = os.path.join("usuarios", user)
            public_key_path = os.path.join(user_dir, "clave_publica.pem")
            cert_path = os.path.join(user_dir, "certificado.json")

            if not os.path.exists(public_key_path) or not os.path.exists(cert_path):
                messagebox.showerror(
                    "Error de Certificado", 
                    f"No se encontró la clave pública o el certificado del usuario '{user}'. Operación cancelada."
                )
                return

            # Verificar el certificado
            if not verificar_certificado_usuario(user):
                messagebox.showerror(
                    "Error de Certificado", 
                    f"El certificado del usuario '{user}' no es válido. Operación cancelada."
                )
                return  # Detener la operación si el certificado no es válido

            # Leer clave pública del usuario y cifrar clave AES
            with open(public_key_path, 'rb') as pub_file:
                public_key = serialization.load_pem_public_key(pub_file.read())
            encrypted_key = encrypt_key_with_rsa(key, public_key)

            # Añadir al header (ID usuario:clave cifrada)
            header.append(f"{user}:{encrypted_key.hex()}")

        # Agregar usuario que realiza el cifrado a la cabecera (siempre)
        header.insert(0, f"{loaded_username}:{encrypt_key_with_rsa(key, loaded_public_key).hex()}")

        # Guardar archivo cifrado con cabecera
        with open(filepath, 'wb') as file:
            file.write("\n".join(header).encode() + b"\n===\n" + iv + ciphertext)

        messagebox.showinfo("Éxito", "Archivo cifrado con éxito.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar archivo: {e}")


# Descifrado de Archivo con Verificación de Cabecera
def decrypt_file_with_header(filepath):
    """Descifra un archivo verificando la cabecera para permitir acceso."""
    try:
        global loaded_private_key, loaded_username

        # Leer archivo completo
        with open(filepath, "rb") as file:
            content = file.read()

        # Separar cabecera y datos
        header_end_index = content.index(b"===\n")
        header = content[:header_end_index].decode().strip().split("\n")
        data = content[header_end_index + 4:]

        # Verificar acceso del usuario
        user_found = False
        key = None
        for entry in header:
            user_id, encrypted_key = entry.split(":")
            encrypted_key = bytes.fromhex(encrypted_key)  # Convertir de hexadecimal a bytes

            if user_id == loaded_username:
                # Intentar descifrar clave con clave privada
                try:
                    key = decrypt_key_with_rsa(encrypted_key, loaded_private_key)
                    user_found = True
                    break
                except Exception:
                    continue

        if not user_found or not key:
            messagebox.showinfo("Error", "No tienes acceso para descifrar este archivo.")
            return

        # Descifrar datos
        iv = data[:16]
        ciphertext = data[16:]
        plaintext = decrypt_data(ciphertext, key, iv, cipher_mode_var.get())

        # Guardar archivo descifrado
        with open(filepath, "wb") as file:
            file.write(plaintext)

        messagebox.showinfo("Éxito", f"Archivo descifrado y guardado en {filepath}.")
    except Exception as e:
        messagebox.showerror("Error", str(e))




# ------------------------------------ Cifrado y Descifrado de Texto ------------------------------------ # 




# Cifra un texto ingresado por el usuario y guarda el archivo cifrado, cifrando la clave AES con RSA si es necesario.
def encrypt_text():
    """Cifra un texto ingresado en un cuadro de texto y añade cabeceras con claves cifradas para usuarios."""
    try:
        global loaded_public_key, loaded_username

        # Verificar el certificado del usuario que está cifrando
        if not verificar_certificado_usuario(loaded_username):
            messagebox.showerror(
                "Error de Certificado",
                f"El certificado del usuario '{loaded_username}' no es válido. Operación cancelada."
            )
            return  # Detener la operación si el certificado no es válido

        # Obtener el texto a cifrar
        text = text_input.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showwarning("Advertencia", "El texto está vacío.")
            return

        # Obtener parámetros de cifrado
        key_size = int(key_size_var.get())
        mode = cipher_mode_var.get()

        # Generar clave AES y IV
        key = generate_key(key_size)
        iv = generate_iv() if mode != "ECB" else b''

        # Cifrar el texto con AES
        ciphertext = encrypt_data(text.encode('utf-8'), key, iv, mode)

        # Seleccionar usuarios adicionales de la lista
        selected_indices = user_list.curselection()
        selected_users = [user_list.get(i) for i in selected_indices]

        # Construir cabecera
        header = []

        # Verificar certificados y cifrar la clave AES para cada usuario
        for user in selected_users:
            user_dir = os.path.join("usuarios", user)
            public_key_path = os.path.join(user_dir, "clave_publica.pem")
            cert_path = os.path.join(user_dir, "certificado.json")

            if not os.path.exists(public_key_path) or not os.path.exists(cert_path):
                messagebox.showerror(
                    "Error de Certificado",
                    f"No se encontró la clave pública o el certificado del usuario '{user}'. Operación cancelada."
                )
                return

            # Verificar el certificado
            if not verificar_certificado_usuario(user):
                messagebox.showerror(
                    "Error de Certificado",
                    f"El certificado del usuario '{user}' no es válido. Operación cancelada."
                )
                return  # Detener la operación si el certificado no es válido

            # Leer clave pública del usuario y cifrar clave AES
            with open(public_key_path, 'rb') as pub_file:
                public_key = serialization.load_pem_public_key(pub_file.read())
            encrypted_key = encrypt_key_with_rsa(key, public_key)

            # Añadir al header (ID usuario:clave cifrada)
            header.append(f"{user}:{encrypted_key.hex()}")

        # Agregar usuario que realiza el cifrado a la cabecera
        header.insert(0, f"{loaded_username}:{encrypt_key_with_rsa(key, loaded_public_key).hex()}")

        # Guardar el texto cifrado con cabecera
        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Encrypted files", "*.txt")])
        if save_path:
            with open(save_path, 'wb') as file:
                file.write("\n".join(header).encode() + b"\n===\n" + iv + ciphertext)

            messagebox.showinfo("Éxito", f"Texto cifrado guardado en {save_path}.")
        else:
            messagebox.showwarning("Advertencia", "No se seleccionó ningún archivo para guardar el texto cifrado.")
    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar texto: {e}")





# ------------------------------------ Certificados Digitales ------------------------------------ # 




# Genera una clave AES a partir de una licencia utilizando SHA-256 y PBKDF2.
def generate_aes_key_from_license():
    # Definir la licencia directamente en la función (por ejemplo, como una cadena)
    license_key = "LICENCIA12345"  # Ejemplo de licencia, puedes cambiarlo por la que necesites

    # Crear un hash de la licencia con SHA-256
    license_hash = hashlib.sha256(license_key.encode()).digest()
    
    # Derivar la clave AES usando PBKDF2 (esto garantiza que obtengas una clave de 256 bits)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits para la clave AES
        salt=license_hash[:16],  # Usamos una parte del hash de la licencia como 'salt'
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(license_hash)  # Derivar la clave

    return aes_key

# Cifra la clave privada del root utilizando AES.
def encrypt_root_private_key():
    root_dir = "usuarios/root"  # La carpeta del usuario Root

    # Asegúrate de que la carpeta existe
    if not os.path.exists(root_dir):
        os.makedirs(root_dir)  # Crear la carpeta si no existe

    # Rutas de los archivos de la clave privada, archivo cifrado de salida y clave AES
    private_key_path = os.path.join(root_dir, "clave_privada.pem")
    encrypted_key_path = os.path.join(root_dir, "clave_privada_cifrada_con_aes_key.bin")
    aes_key_path = os.path.join(root_dir, "aes_key.bin")

    # Comprobar si el archivo de clave privada existe
    if not os.path.exists(private_key_path):
        messagebox.showinfo("No se encuentra la clave privada de Root.")
        return

    # Leer la clave privada de Root desde el archivo
    with open(private_key_path, "rb") as priv_file:
        private_key_data = priv_file.read()

    # Obtener la clave AES generada a partir de la licencia
    aes_key = generate_aes_key_from_license()

    # Guardar la clave AES en un archivo dentro del directorio Root
    with open(aes_key_path, "wb") as aes_file:
        aes_file.write(aes_key)

    # Generar un IV (vector de inicialización) aleatorio para el cifrado
    iv = os.urandom(16)

    # Configuración del cifrador AES (modo CBC)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Usar la función de padding para asegurar que la clave privada tenga el tamaño adecuado
    padded_data = pad_data(private_key_data)

    # Cifrar la clave privada
    encrypted_private_key = encryptor.update(padded_data) + encryptor.finalize()

    # Guardar el archivo cifrado de la clave privada
    with open(encrypted_key_path, "wb") as encrypted_file:
        encrypted_file.write(iv + encrypted_private_key)  # Guardamos el IV junto con los datos cifrados




# ---------------------------------------- CERTIFICADOS ------------------------------------------ # 




# Crea un certificado digital para un usuario, firmando su clave pública con la clave privada del root.
def create_user_certificate(username):
    # Ruta del directorio del usuario
    user_dir = f"usuarios/{username}"
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)

    # Ruta al archivo de la clave pública del usuario
    public_key_path = os.path.join(user_dir, "clave_publica.pem")
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"No se encontró la clave pública para el usuario {username}.")

    # Leer la clave pública del usuario
    with open(public_key_path, "rb") as pub_file:
        user_public_key_data = pub_file.read()

    # Ruta del directorio del root
    root_dir = "usuarios/root"
    aes_key_path = os.path.join(root_dir, "aes_key.bin")
    encrypted_private_key_path = os.path.join(root_dir, "clave_privada_cifrada_con_aes_key.bin")
    
    if not os.path.exists(aes_key_path) or not os.path.exists(encrypted_private_key_path):
        raise FileNotFoundError("No se encontraron los archivos necesarios para la clave privada del usuario root.")

    # Leer la clave AES
    with open(aes_key_path, "rb") as aes_file:
        aes_key = aes_file.read()

    # Leer y descifrar la clave privada del root
    with open(encrypted_private_key_path, "rb") as enc_priv_file:
        encrypted_private_key_data = enc_priv_file.read()

    # El vector de inicialización (IV) está almacenado en los primeros 16 bytes
    iv = encrypted_private_key_data[:16]
    encrypted_private_key = encrypted_private_key_data[16:]

    # Configuración del cifrador AES (modo CBC)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Descifrar la clave privada
    private_key_data = decryptor.update(encrypted_private_key) + decryptor.finalize()

    # Cargar la clave privada del root
    root_private_key = serialization.load_pem_private_key(
        private_key_data,
        password=None,
        backend=default_backend()
    )

    # Crear el hash (huella digital) del certificado (username + clave pública)
    hash_input = username.encode() + user_public_key_data
    fingerprint = hashlib.sha256(hash_input).digest()

    # Firmar el hash con la clave privada del root
    signature = root_private_key.sign(
        fingerprint,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Crear el contenido del certificado
    certificate_data = {
        "username": username,
        "public_key": user_public_key_data.decode('utf-8'),
        "signature": signature.hex(),
    }

    # Ruta para guardar el certificado
    certificate_path = os.path.join(user_dir, "certificado.json")

    # Guardar el certificado en formato JSON
    with open(certificate_path, "w") as cert_file:
        json.dump(certificate_data, cert_file, indent=4)

# Verifica un certificado digital, asegurándose de que la firma coincida con la clave pública del root.
def verificar_certificado_usuario(username):
    """Verifica el certificado de un usuario específico."""
    try:
        user_dir = os.path.join("usuarios", username)
        ruta_certificado_usuario = os.path.join(user_dir, "certificado.json")
        ruta_clave_publica_root = os.path.join("usuarios", "root", "clave_publica.pem")

        # 1. Cargar certificado y clave pública del root
        with open(ruta_certificado_usuario, "r") as f:
            certificado = json.load(f)
        with open(ruta_clave_publica_root, "rb") as f:
            clave_publica_root = serialization.load_pem_public_key(f.read())

        # 2. Extraer datos del certificado
        nombre_usuario = certificado["username"]
        clave_publica_usuario = certificado["public_key"]
        firma = certificado["signature"]

        # 3. Convertir firma de hex a bytes
        firma = bytes.fromhex(firma)

        # 4. Concatenar datos originales para generar el hash (huella digital)
        datos_originales = nombre_usuario.encode() + clave_publica_usuario.encode()

        # Crear el hash (huella digital)
        hash_generado = hashlib.sha256(datos_originales).digest()

        # 5. Verificar la firma usando la clave pública del root
        clave_publica_root.verify(
            firma,
            hash_generado,  # Se usa el hash generado a partir de los datos originales
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        messagebox.showinfo("Certificado Verificado", f"El certificado del usuario '{username}' es válido.")
        return True
    except Exception as e:
        messagebox.showinfo(f"Error al verificar el certificado del usuario {username}: {e}", f"Hay algun certificado que no es verídico")
        return False




# ------------------------------------ Interfaz Gráfica (UI) ------------------------------------ # 




# Abre la ventana principal de la aplicación, donde el usuario puede elegir opciones de cifrado y descifrado.                        
def open_main_window():
    global key_size_var, cipher_mode_var, rsa_option, text_input, user_list, loaded_username

    main_window = tk.Toplevel()
    main_window.title("Cifrado de Archivos con AES y RSA")
    main_window.geometry("550x350")
    main_window.config(bg="#f0f0f0")

    # Tamaño de clave AES
    key_size_var = tk.StringVar(value="256")
    cipher_mode_var = tk.StringVar(value="CBC")
    rsa_option = tk.IntVar(value=0)

    # Configuración de claves y modos
    #key_size_label = ttk.Label(main_window, text="Tamaño de la clave AES:")
    #key_size_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

    #key_size_options = ["128","128", "192", "256"]
    #key_size_menu = ttk.OptionMenu(main_window, key_size_var, *key_size_options)
    #key_size_menu.grid(row=0, column=1, padx=10, pady=10, sticky="w")

    #cipher_mode_label = ttk.Label(main_window, text="Modo de cifrado:")
    #cipher_mode_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

    #cipher_mode_options = ["CBC","CBC", "CFB", "ECB"]
    #cipher_mode_menu = ttk.OptionMenu(main_window, cipher_mode_var, *cipher_mode_options)
    #cipher_mode_menu.grid(row=1, column=1, padx=10, pady=10, sticky="w")

    # Lista de usuarios
    ttk.Label(main_window, text="Selecciona usuarios adicionales:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
    user_list = tk.Listbox(main_window, selectmode="multiple", height=5, exportselection=False)
    user_list.grid(row=3, column=1, padx=10, pady=10, sticky="w")

    # Cargar usuarios en el listado
    user_dir = "usuarios"
    if os.path.exists(user_dir):
        for user in os.listdir(user_dir):
            if user != loaded_username:  # Evitar incluir al usuario actual
                user_list.insert(tk.END, user)

    # Botón para cifrar archivo con usuarios seleccionados
    encrypt_button = ttk.Button(main_window, text="Cifrar Archivo", command=encrypt_with_selected_users)
    encrypt_button.grid(row=4, column=0, padx=10, pady=10)

    # Botón para descifrar archivo con cabecera
    def decrypt_file_with_header_action():
        filepath = filedialog.askopenfilename(
            title="Selecciona el archivo para descifrar",
            filetypes=[("All files", "*.*"), ("Encrypted files", "*.enc"), ("Text files", "*.txt")]
        )
        if filepath:
            decrypt_file_with_header(filepath)

    decrypt_button = ttk.Button(main_window, text="Descifrar Archivo", command=decrypt_file_with_header_action)
    decrypt_button.grid(row=4, column=1, padx=10, pady=10)

    # Campo de entrada de texto para cifrar
    text_input_label = ttk.Label(main_window, text="Texto a cifrar:")
    text_input_label.grid(row=5, column=0, padx=10, pady=10, sticky="w")

    text_input = tk.Text(main_window, height=4, width=40, font=("Arial", 10))
    text_input.grid(row=5, column=1, padx=10, pady=10, sticky="w")

    # Botón para cifrar texto
    encrypt_text_button = ttk.Button(main_window, text="Cifrar Texto", command=encrypt_text)
    encrypt_text_button.grid(row=6, column=1, pady=10)
    
    # Botón para cifrar archivo con Kyber
    kyber_encrypt_button = ttk.Button(main_window, text="Cifrar Archivo con Kyber", command=encrypt_file_with_kyber)
    kyber_encrypt_button.grid(row=10, column=0, padx=10, pady=20)

    # Botón para descifrar archivo con Kyber
    kyber_decrypt_button = ttk.Button(main_window, text="Descifrar Archivo con Kyber", command=decrypt_file_with_kyber)
    kyber_decrypt_button.grid(row=10, column=1, padx=10, pady=10)

    # Mantener ventana principal abierta
    main_window.mainloop()

# Muestra la ventana de inicio de sesión para el usuario, permitiendo autenticarse o registrarse.
def login():
    initial_window = tk.Tk()
    initial_window.title("Login")
    initial_window.geometry("300x200")
    
    username_label = ttk.Label(initial_window, text="Nombre de usuario:")
    username_label.pack(pady=5)
    username_entry = ttk.Entry(initial_window, width=30)
    username_entry.pack(pady=5)
    
    password_label = ttk.Label(initial_window, text="Contraseña:")
    password_label.pack(pady=5)
    password_entry = ttk.Entry(initial_window, width=30, show="*")
    password_entry.pack(pady=5)

    def handle_login():
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            login_action(username, password)
            initial_window.withdraw()
            
        else:
            messagebox.showinfo("Error", "Debe ingresar un nombre de usuario y contraseña.")

    def identificacion():
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            identificacion_login(username, password)
            initial_window.withdraw()
        else:
            messagebox.showinfo("Error", "Debe ingresar un nombre de usuario y contraseña.")

    login_button = ttk.Button(initial_window, text="Iniciar Sesión", command=identificacion)
    login_button.pack(side="left", padx=35, pady=20)

    create_account_button = ttk.Button(initial_window, text="Crear Cuenta", command=handle_login)
    create_account_button.pack(side="right", padx=35, pady=20)

    initial_window.mainloop()




# ------------------------------------ Gestión de Cuentas y Autenticación ------------------------------------ # 




# Crea una nueva cuenta para el usuario, generando las claves RSA, cifrando la contraseña y almacenándola.
def login_action(username, password):
    global loaded_private_key, loaded_public_key, loaded_username, loaded_password  # Claves accesibles globalmente

    user_dir = os.path.join("usuarios", username)

    if not os.path.exists(user_dir):
        # Crear carpeta para el nuevo usuario
        os.makedirs(user_dir)
        messagebox.showinfo("Usuario creado", f"Carpeta creada para el usuario: {username}")
        
        # Generar y guardar las claves RSA
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(private_key, public_key, user_dir)
        messagebox.showinfo("Claves generadas", f"Claves RSA generadas y guardadas para el usuario: {username}")

        # Cifrar y guardar la contraseña
        encrypted_password = encrypt_key_with_rsa(password.encode(), public_key)
        password_filepath = os.path.join(user_dir, "password_del_login_cifrada.bin")
        with open(password_filepath, 'wb') as password_file:
            password_file.write(encrypted_password)
        messagebox.showinfo("Contraseña cifrada", f"La contraseña ha sido cifrada y guardada en {password_filepath}")

    else:
        messagebox.showinfo("Usuario existente", f"El usuario {username} ya existe. No se generan nuevas claves.")

    # Ahora cargar las claves y asignar los valores globales
    private_key_filepath = os.path.join(user_dir, "clave_privada.pem")
    public_key_filepath = os.path.join(user_dir, "clave_publica.pem")

    # Verificar que las claves existan
    if not os.path.exists(private_key_filepath) or not os.path.exists(public_key_filepath):
        messagebox.showinfo("Error", "Las claves pública o privada no se encontraron.")
        return

    try:
        # Cargar la clave privada
        with open(private_key_filepath, 'rb') as private_key_file:
            loaded_private_key = serialization.load_pem_private_key(
                private_key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Cargar la clave pública
        with open(public_key_filepath, 'rb') as public_key_file:
            loaded_public_key = serialization.load_pem_public_key(
                public_key_file.read(),
                backend=default_backend()
            )

        # Si el usuario no es "root", realizar las acciones adicionales
        if username != "root":
            # Generar el hash de la contraseña
            password_hash = hashlib.sha256(password.encode()).digest()
            with open(os.path.join(user_dir, "password_hash.bin"), "wb") as hash_file:
                hash_file.write(password_hash)

            # Derivar una clave AES usando el hash de la contraseña
            aes_key = derive_aes_key_from_password(password_hash)

            # Cifrar la clave privada con AES
            private_key_encrypted, iv = encrypt_private_key_with_aes(loaded_private_key, aes_key)
            with open(os.path.join(user_dir, "clave_privada_cifrada.bin"), "wb") as encrypted_key_file:
                encrypted_key_file.write(iv + private_key_encrypted)

        # Asignar el nombre de usuario y la contraseña a las variables globales
        loaded_username = username
        loaded_password = password

    except Exception as e:
        messagebox.showinfo("Error", f"Error al cargar las claves: {str(e)}")
        return

    # Acciones específicas si el usuario es "root"
    if username == "root":
        encrypt_root_private_key()

    if username != "root":
        create_user_certificate(username)

    # Eliminar el archivo de clave privada sin cifrar
    os.remove(private_key_filepath)

    open_main_window()  # Abrir la ventana principal después de todo


# Verifica una cuenta existente, cargando las claves y validando la contraseña cifrada del usuario.
def identificacion_login(username, password):
    global loaded_private_key, loaded_public_key, loaded_username, loaded__password  # Claves accesibles globalmente
    user_dir = os.path.join("usuarios", username)

    if not os.path.exists(user_dir):
        messagebox.showinfo("Error", "El usuario no existe. Por favor, regístrese primero.")
        return  

    password_hash_path = os.path.join(user_dir, "password_hash.bin")
    encrypted_private_key_path = os.path.join(user_dir, "clave_privada_cifrada.bin")
    public_key_filepath = os.path.join(user_dir, "clave_publica.pem")

    # Verificar existencia de las claves
    if not all(os.path.exists(path) for path in [password_hash_path, encrypted_private_key_path, public_key_filepath]):
        messagebox.showinfo("Error", "Archivos necesarios para la autenticación no encontrados.")
        return

    try:
        # Leer y verificar el hash de la contraseña
        with open(password_hash_path, "rb") as hash_file:
            stored_password_hash = hash_file.read()

        derived_password_hash = hashlib.sha256(password.encode()).digest()
        if stored_password_hash != derived_password_hash:
            messagebox.showinfo("Error", "Contraseña incorrecta.")
            return

        # Derivar clave AES y descifrar clave privada
        aes_key = derive_aes_key_from_password(stored_password_hash)
        with open(encrypted_private_key_path, "rb") as encrypted_key_file:
            encrypted_data = encrypted_key_file.read()
            iv, encrypted_private_key = encrypted_data[:16], encrypted_data[16:]

        loaded_private_key = decrypt_private_key_with_aes(encrypted_private_key, aes_key, iv)

        # Cargar la clave pública
        with open(public_key_filepath, 'rb') as public_key_file:
            loaded_public_key = serialization.load_pem_public_key(
                public_key_file.read(),
                backend=default_backend()
            )

        # Asignar el nombre de usuario a la variable global
        loaded_username = username  
        loaded__password = password
        

    except Exception as e:
        messagebox.showinfo("Error", f"Error al cargar las claves: {str(e)}")
        return

    # Validar la contraseña
    password_filepath = os.path.join(user_dir, "password_del_login_cifrada.bin")
    if not os.path.exists(password_filepath):
        messagebox.showinfo("Error", "No se encontró el archivo de contraseña cifrada.")
        return

    with open(password_filepath, 'rb') as password_file:
        encrypted_password = password_file.read()

    try:
        decrypted_password = loaded_private_key.decrypt(
            encrypted_password,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=SHA256()),
                algorithm=SHA256(),
                label=None
            )
        ).decode('utf-8')
    except Exception as e:
        messagebox.showinfo("Error", f"Error al desencriptar la contraseña: {str(e)}")
        return

    if decrypted_password == password:
        messagebox.showinfo("Bienvenido", f"Inicio de sesión exitoso para {username}")
        open_main_window()
    else:
        messagebox.showinfo("Error", "Contraseña incorrecta.")

# ------------------------------------ KYBER ------------------------------------ # 


def encrypt_file_with_kyber():
    try:
        # Seleccionamos el archivo original que se desea cifrar
        input_filepath = filedialog.askopenfilename(
            title="Selecciona el archivo que deseas cifrar con Kyber",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("PDF files", "*.pdf"), ("Images", "*.png")]
        )
        if not input_filepath:
            return

        # Generar par de claves Kyber
        public_key, private_key  = generate_keypair()

        # Verificar tamaños de las claves
        if len(public_key) != 800:
            raise ValueError(f"Tamaño de la clave pública incorrecto: {len(public_key)}")
        if len(private_key) != 1632:
            raise ValueError(f"Tamaño de la clave privada incorrecto: {len(private_key)}")

        # Obtener el directorio del archivo original
        encrypted_filepath = input_filepath + '.kyber.enc'
        encrypted_dir = os.path.dirname(encrypted_filepath)

        # Guardar claves en el mismo directorio del archivo cifrado
        public_key_filepath = os.path.join(encrypted_dir, 'public_key.pub')
        private_key_filepath = os.path.join(encrypted_dir, 'private_key.priv')

        with open(public_key_filepath, 'wb') as pub_file:
            pub_file.write(public_key)
        with open(private_key_filepath, 'wb') as priv_file:
            priv_file.write(private_key)

        # Leer datos del archivo original
        with open(input_filepath, 'rb') as file:
            file_data = file.read()

        # Generar secreto compartido y ciphertext con Kyber
        ciphertext, shared_secret = encrypt(public_key)

        # Usar el secreto compartido para AES
        aes_key = shared_secret[:32]  # AES-256 requiere 32 bytes
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Añadir padding correctamente
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()

        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Sobrescribir el archivo original con los datos cifrados
        with open(input_filepath, 'wb') as encrypted_file:
            encrypted_file.write(iv + encrypted_data)

        # Guardar el ciphertext en el mismo directorio
        ciphertext_filepath = os.path.join(encrypted_dir, 'ciphertext.ct')
        with open(ciphertext_filepath, 'wb') as ciphertext_file:
            ciphertext_file.write(ciphertext)

        messagebox.showinfo("Éxito", f"Archivo cifrado y sobrescrito: {input_filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Error al cifrar con Kyber: {e}")



def decrypt_file_with_kyber():
    try:
        encrypted_filepath = filedialog.askopenfilename(
            title="Selecciona el archivo cifrado con Kyber",
            filetypes=[("Encrypted files", "*.pdf")]
        )
        if not encrypted_filepath:
            return

        # Obtener el directorio del archivo cifrado
        encrypted_dir = os.path.dirname(encrypted_filepath)
        
        # Buscar automáticamente el archivo de clave privada en el mismo directorio
        private_key_filepath = os.path.join(encrypted_dir, 'private_key.priv')
        if not os.path.exists(private_key_filepath):
            raise FileNotFoundError(f"No se encontró la clave privada en {encrypted_dir}")

        ciphertext_filepath = os.path.join(encrypted_dir, 'ciphertext.ct')
        if not os.path.exists(ciphertext_filepath):
            raise FileNotFoundError(f"No se encontró el archivo de ciphertext en {encrypted_dir}")

        # Leer datos de los archivos
        with open(private_key_filepath, 'rb') as priv_file:
            private_key = priv_file.read()
        with open(ciphertext_filepath, 'rb') as ct_file:
            ciphertext = ct_file.read()
        with open(encrypted_filepath, 'rb') as enc_file:
            encrypted_data = enc_file.read()

        # Descifrar el secreto compartido
        shared_secret = decrypt(private_key, ciphertext)

        # Usar el secreto compartido para descifrar con AES
        aes_key = shared_secret[:32]
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Eliminar padding correctamente
        unpadder = padding.PKCS7(128).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()

        # Guardar archivo descifrado
        original_filepath = encrypted_filepath.replace('.kyber.enc', '.decrypted')
        with open(original_filepath, 'wb') as output_file:
            output_file.write(original_data)

        messagebox.showinfo("Éxito", f"Archivo descifrado guardado en:\n{original_filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Error al descifrar con Kyber: {e}")



# ------------------------------------ Protección de Claves Privadas con AES Derivado de Contraseñas ------------------------------------ # 




# Derivación de Clave AES desde un Hash de Contraseña
def derive_aes_key_from_password(password_hash):
    # Derivar la clave AES
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=password_hash[:16],  # Usar parte del hash como salt
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password_hash)

# Cifrado de Clave Privada Usando AES-CBC
def encrypt_private_key_with_aes(private_key, aes_key):
    # Convertir la clave privada a bytes
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generar un vector de inicialización (IV) aleatorio
    iv = os.urandom(16)

    # Cifrar con AES en modo CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Asegurarse de que los datos sean múltiplos de 16 (bloque AES)
    pad_length = 16 - len(private_key_bytes) % 16
    padded_private_key = private_key_bytes + bytes([pad_length]) * pad_length

    encrypted_data = encryptor.update(padded_private_key) + encryptor.finalize()
    return encrypted_data, iv

# Descifrado de Clave Privada Usando AES-CBC
def decrypt_private_key_with_aes(encrypted_private_key, aes_key, iv):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_key = decryptor.update(encrypted_private_key) + decryptor.finalize()

    # Eliminar el padding
    pad_length = decrypted_padded_key[-1]
    decrypted_key = decrypted_padded_key[:-pad_length]

    return serialization.load_pem_private_key(decrypted_key, password=None, backend=default_backend())




# -------------------------------------------- Variables globales -------------------------------------------- #




# Variables globales para almacenar las claves cargadas automáticamente
loaded_private_key = None
loaded_public_key = None
loaded_username = None
loaded__password = None



# -------------------------------------------- MAIN -------------------------------------------- #




login()

