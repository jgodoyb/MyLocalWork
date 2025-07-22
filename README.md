# Cryptographic Toolkit - Secure Data Management 🔐

## Overview

MyLocalWork is a robust cryptographic toolkit that enables developers to implement secure data encryption, key management, and cryptographic operations. This application integrates classical cryptography methods like RSA and AES with a hierarchical certificate-based authentication system, providing a comprehensive security solution for sensitive data management.

-----

## Key Features

  * **Multi-user Encryption System**: Encrypt files for multiple recipients simultaneously.
  * **Certificate-based Authentication**: Hierarchical PKI with root-signed user certificates.
  * **Secure Key Management**: AES-256 protected private keys with password derivation.
  * **Hybrid Cryptography**: Combines symmetric (AES) and asymmetric (RSA) encryption.
  * **Multiple Encryption Modes**: Supports CBC, CFB, and ECB modes for flexible security.
  * **GUI Interface**: Intuitive graphical interface for cryptographic operations.

-----

## Security Architecture

DiagramCode (Consider embedding an image here if you have a diagram, e.g., `![Architecture Diagram](images/architecture.png)`)

-----

## Prerequisites

  * Python 3.7 or higher

  * Required libraries:

    ```bash
    pip install cryptography
    pip install tkinter
    ```

-----

## Installation & Setup

### 1\. Initialize Root User (First-Time Setup)

1.  **Run the application:**

    ```bash
    python crypto_app.py
    ```

2.  **In the login window:**

      * Username: `root`
      * Password: `[Choose a strong password]`
      * Click `"Create Account"`

    The system will automatically generate:

      * RSA key pair (2048-bit) for root authority
      * Digital certificate for root identity
      * AES-encrypted private key storage
      * Password verification system

### 2\. Create Standard Users

1.  Run the application again.

2.  For each user:

      * Enter new username and password.
      * Click `"Create Account"`.

    The system will generate:

      * Personal RSA key pair
      * Root-signed digital certificate
      * Password-protected private key storage

-----

## Technical Components

### Core Cryptographic Functions

  * **Key Generation:**

    ```python
    def generate_rsa_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return private_key, private_key.public_key()
    ```

  * **Data Encryption:**

    ```python
    def encrypt_data(data, key, iv, mode):
        cipher_mode = modes.CBC(iv) if mode == "CBC" else ...
        cipher = Cipher(algorithms.AES(key), cipher_mode)
        encryptor = cipher.encryptor()
        return encryptor.update(pad_data(data)) + encryptor.finalize()
    ```

  * **Certificate Management:**

    ```python
    def create_user_certificate(username):
        # Generate digital signature using root private key
        signature = root_private_key.sign(
            user_public_key_data,
            padding.PSS(...),
            hashes.SHA256()
        )
        # Store certificate with username, public key, and signature
    ```

### Security Measures

  * **Private Key Protection:**

    ```python
    def encrypt_private_key_with_aes(private_key, aes_key):
        # Convert private key to bytes
        private_key_bytes = private_key.private_bytes(...)
        # Generate random IV
        iv = os.urandom(16)
        # Encrypt using AES-CBC
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        return encrypted_data, iv
    ```

  * **Password Key Derivation:**

    ```python
    def derive_aes_key_from_password(password_hash):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=password_hash[:16],
            iterations=100000
        )
        return kdf.derive(password_hash)
    ```

-----

## File Structure

```text
users/
├── root/
│   ├── public_key.pem
│   ├── encrypted_private_key.bin
│   ├── aes_key.bin
│   └── certificate.json
├── alice/
│   ├── public_key.pem
│   ├── encrypted_private_key.bin
│   ├── certificate.json
│   └── password_hash.bin
└── bob/
    ├── public_key.pem
    ├── encrypted_private_key.bin
    ├── certificate.json
    └── password_hash.bin
```

-----

## Security Features

  * **Hierarchical Certificate Authority:**
      * Root-signed user certificates
      * Automatic certificate verification before operations
      * Certificate revocation support
  * **Key Protection:**
      * AES-256 encrypted private keys
      * PBKDF2 password derivation (100,000 iterations)
      * Memory-resident keys cleared after use
  * **Cryptographic Best Practices:**
      * PKCS\#7 padding for block alignment
      * Random IV generation for each operation
      * SHA-256 for all hashing operations
  * **Access Control:**
      * File header-based permission system
      * Multi-recipient encrypted key distribution
      * Certificate-based identity verification

-----

## Important Notes

  * The **root user must be created first** - this establishes the certificate authority.
  * User certificates are automatically generated during account creation.
  * Encrypted files contain access headers with recipient information.
  * All cryptographic operations verify certificate validity.
  * Private keys are never stored in plaintext format.

-----
