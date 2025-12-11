#Divya Patel ECE 56401- Computer Security - Final Project
#Least Siginigicant Bit Implementation
#Project Description:
#Core module for embedding and extracting data using Least Significant Bit technique
#Features: Magic header validation, SHA-256 integrity checks, AES encryption support

import struct
from hashlib import sha256
from crypto_utils import aes_encrypt, aes_decrypt

from .utils import (
    load_image_flat,
    save_image_flat,
    bytes_to_bits,
    bits_to_bytes,
    check_capacity,
    StegoCapacityError,
)

class StegoError(Exception):
    """Custom exception for steganography errors."""
    pass


MAGIC = b"STGO"       # 4-byte identifier
VERSION = bytes([1])  # version = 1


def lsb_embed(cover_path, payload_bytes, output_path, password=None):
    """
    Embed payload into cover image using LSB replacement.
    Adds: MAGIC header, version byte, 4-byte length header, 
    SHA-256 integrity hash, and optional AES encryption.
    """
    # Load image as flat array and get original shape
    flat, shape = load_image_flat(cover_path)

    # Encrypt payload if password provided
    if password:
        payload_final = aes_encrypt(payload_bytes, password)
    else:
        payload_final = payload_bytes

    # Calculate SHA-256 hash of original payload for integrity checking
    digest = sha256(payload_bytes).digest()  # 32 bytes

    # Build header with payload length (4 bytes, big-endian)
    header = struct.pack(">I", len(payload_final))

    # Combine all components: magic + version + length + hash + payload
    full_payload = MAGIC + VERSION + header + digest + payload_final

    # Check if image has enough pixels to hold the data
    check_capacity(flat, payload_len_bytes=len(full_payload), header_bytes=0)

    # Convert full payload to bits (list of 0s and 1s)
    bits = bytes_to_bits(full_payload)

    # Embed each bit into LSB of each pixel value
    for i, bit in enumerate(bits):
        # Clear LSB and set to our bit: XXXXXXX0 -> XXXXXXXbit
        flat[i] = (flat[i] & 0b11111110) | bit

    # Save the modified image
    save_image_flat(flat, shape, output_path)


def lsb_extract(stego_path, password=None):
    """
    Extract and validate payload from stego image.
    Steps: read MAGIC, version, length, SHA-256 digest, 
    encrypted payload, decrypt if needed, and verify integrity.
    """
    flat, _ = load_image_flat(stego_path)

    # Extract magic header (first 32 bits = 4 bytes)
    magic_bits = [(flat[i] & 1) for i in range(32)]
    magic = bits_to_bytes(magic_bits)
    if magic != MAGIC:
        raise StegoError("Invalid stego file — MAGIC mismatch.")

    # Extract version (next 8 bits = 1 byte)
    version_bits = [(flat[i] & 1) for i in range(32, 40)]
    version = bits_to_bytes(version_bits)[0]
    if version != 1:
        raise StegoError(f"Unsupported version: {version}")

    # Extract payload length (next 32 bits = 4 bytes)
    length_bits = [(flat[i] & 1) for i in range(40, 72)]
    length_bytes = bits_to_bytes(length_bits)
    payload_len = struct.unpack(">I", length_bytes)[0]

    # Extract stored SHA-256 hash (next 256 bits = 32 bytes)
    digest_start = 72
    digest_end = 72 + 32 * 8
    digest_bits = [(flat[i] & 1) for i in range(digest_start, digest_end)]
    stored_digest = bits_to_bytes(digest_bits)

    # Extract the main payload data
    payload_start = digest_end
    payload_end = payload_start + payload_len * 8
    payload_bits = [(flat[i] & 1) for i in range(payload_start, payload_end)]
    payload_encrypted = bits_to_bytes(payload_bits)

    # Decrypt if password was used during embedding
    if password:
        payload_plain = aes_decrypt(payload_encrypted, password)
    else:
        payload_plain = payload_encrypted

    # Verify data integrity by comparing hash of extracted data
    computed_digest = sha256(payload_plain).digest()
    if computed_digest != stored_digest:
        raise StegoError("Integrity check FAILED — wrong password or corrupted data.")

    return payload_plain