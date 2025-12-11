#Divya Patel ECE 56401- Computer Security - Final Project
#Utility helpers
#Project Description:
#Exception Classes for all functions below
#loading and saving images (auto remove alpha channel for png images)
#bit/byte conversion helpers
#simple capacity check and small helpers


from PIL import Image
import numpy as np
import os

# Exception classes
class StegoError(Exception):
    pass

class StegoCapacityError(StegoError):
    pass

class InvalidImageError(StegoError):
    pass


#IMAGE HELPERS

def load_image(path):
    """Load image as RGB numpy array."""
    if not os.path.exists(path):
        raise InvalidImageError(f"Image not found: {path}")

    img = Image.open(path).convert("RGB")
    return np.array(img).astype(np.uint8)


def load_image_flat(path):
    """Load flattened RGB pixel array."""
    arr = load_image(path)
    return arr.flatten(), arr.shape


def save_image_flat(flat, shape, out_path):
    arr = flat.reshape(shape).astype(np.uint8)
    img = Image.fromarray(arr, mode="RGB")
    img.save(out_path)


#BIT / BYTE HELPERS

def bytes_to_bits(data: bytes):
    bits = []
    for b in data:
        bits.extend(int(bit) for bit in f"{b:08b}")
    return bits


def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise ValueError("bits length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = int("".join(str(b) for b in bits[i:i+8]), 2)
        out.append(byte)
    return bytes(out)


#CAPACITY HELPERS

def required_capacity_bits(payload_len_bytes, header_bytes=4):
    return (payload_len_bytes + header_bytes) * 8


def check_capacity(flat_array, payload_len_bytes, header_bytes=4):
    needed = required_capacity_bits(payload_len_bytes, header_bytes)
    if needed > flat_array.size:
        raise StegoCapacityError(
            f"Cover too small: need {needed} bits, have {flat_array.size}"
        )
    return True
