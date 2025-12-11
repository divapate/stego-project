#Divya Patel ECE 56401- Computer Security - Final Project
#Enhanced Cryptography Module with PBKDF2 Key Derivation
#Project Description:
#Implements AES-256-CBC encryption with secure key derivation using PBKDF2-HMAC-SHA256
#Features: Random salt generation, unique IV per encryption, 
#password-based encryption with 200,000 iteration rounds

import os
import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def derive_key(password: str, salt: bytes, iterations=200000):
    """
    Derive a 256-bit key from password using PBKDF2-HMAC-SHA256.
    """
    # Create encryption key from password using PBKDF2
    # This makes brute-force attacks much slower
    key = hashlib.pbkdf2_hmac(
        "sha256",                    # Use SHA-256 hash algorithm
        password.encode("utf-8"),    # Convert password to bytes
        salt,                        # Random salt for uniqueness
        iterations,                  # 200,000 rounds of hashing for security
        dklen=32                     # Output 32-byte (256-bit) key for AES-256
    )
    return key


def aes_encrypt(password: str, plaintext: bytes):
    """
    Encrypt plaintext using AES-256-CBC with PBKDF2-derived key.
    Returns: salt || iv || ciphertext
    """
    # Generate random salt - makes each encryption unique even with same password
    salt = secrets.token_bytes(16)
    
    # Create encryption key from password and salt
    key = derive_key(password, salt)
    
    # Generate random initialization vector (IV) for CBC mode
    iv = secrets.token_bytes(16)

    # Create AES cipher in CBC mode with our key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the data to AES block size (16 bytes) and encrypt
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Return: 16 bytes salt + 16 bytes IV + encrypted data
    return salt + iv + ciphertext


def aes_decrypt(password: str, data: bytes):
    """
    Decrypt salt || iv || ciphertext using AES-256-CBC.
    """
    # Split the combined data back into components
    salt = data[:16]        # First 16 bytes are salt
    iv = data[16:32]        # Next 16 bytes are IV  
    ciphertext = data[32:]  # Rest is encrypted data

    # Recreate the same key using password and salt
    key = derive_key(password, salt)
    
    # Create AES cipher with same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt data and remove padding
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext