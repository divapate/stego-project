#Divya Patel ECE 56401- Computer Security - Final Project
#Cryptography Utilities Module
#Project Description:
#Provides AES-256-CBC encryption and decryption functions for securing payloads in steganography operations. 
#Uses SHA-256 for key derivation and PKCS7 padding.

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import struct

# --- KEY DERIVATION ---
def derive_key(password: str) -> bytes:
    """Derive a 256-bit AES key from password using SHA-256."""
    # Create SHA256 hash object
    h = SHA256.new()
    # Add password to hash (convert string to bytes first)
    h.update(password.encode("utf-8"))
    # Get final 32-byte (256-bit) hash as encryption key
    return h.digest()  # 32 bytes


# --- ENCRYPTION ---
def aes_encrypt(data: bytes, password: str) -> bytes:
    """Encrypt payload with AES-CBC. Format: [IV(16 bytes)] + ciphertext."""
    # Get encryption key from password
    key = derive_key(password)
    # Generate random 16-byte Initialization Vector for CBC mode
    iv = get_random_bytes(16)

    # Create AES cipher in CBC mode with our key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # PKCS7 padding - add bytes to make data length multiple of 16
    # Last byte value = number of padding bytes added
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len

    # Encrypt the padded data
    ciphertext = cipher.encrypt(data)
    # Return: 16 bytes IV + encrypted data
    return iv + ciphertext


# --- DECRYPTION ---
def aes_decrypt(enc: bytes, password: str) -> bytes:
    """Decrypt payload. Input must be [IV | ciphertext]."""
    # Check if data has at least IV (16 bytes)
    if len(enc) < 16:
        raise ValueError("Encrypted data too short.")

    # Get same key from password
    key = derive_key(password)
    # Extract IV (first 16 bytes) and ciphertext (rest)
    iv = enc[:16]
    ciphertext = enc[16:]

    # Create AES cipher with same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt data (still has padding)
    padded = cipher.decrypt(ciphertext)

    # Remove padding - last byte tells how many padding bytes to remove
    pad_len = padded[-1]
    # Validate padding length is reasonable (1-16 bytes)
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Bad padding. Wrong password?")

    # Return data without padding bytes
    return padded[:-pad_len]