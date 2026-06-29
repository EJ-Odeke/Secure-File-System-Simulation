"""
==========================================================
File: sefs.py

Purpose:
--------
Simplified Encrypted File System (SEFS)
==========================================================
"""

import os
from crypto.crypto_utils import generate_key, generate_iv, encrypt, decrypt


ENCRYPTED_DIR = "storage/encrypted/"
DECRYPTED_DIR = "storage/decrypted/"
META_DIR = "storage/metadata/"


# Ensure folders exist
def init():
    os.makedirs(ENCRYPTED_DIR, exist_ok=True)
    os.makedirs(DECRYPTED_DIR, exist_ok=True)
    os.makedirs(META_DIR, exist_ok=True)


# Create file (plaintext)
def create_file(username, filename, content):
    init()

    path = DECRYPTED_DIR + filename + ".txt"

    file = open(path, "w")
    file.write(content)
    file.close()

    return 1


# Encrypt file
def encrypt_file(username, filename):
    init()

    input_path = DECRYPTED_DIR + filename + ".txt"
    output_path = ENCRYPTED_DIR + filename + ".enc"

    if not os.path.exists(input_path):
        return -1

    file = open(input_path, "rb")
    data = file.read()
    file.close()

    key = generate_key()
    iv = generate_iv()

    encrypted = encrypt(data, key, iv)

    file = open(output_path, "wb")
    file.write(encrypted)
    file.close()

    # metadata
    meta_path = META_DIR + filename + ".meta"

    meta = f"""username:{username}
key:{key.hex()}
iv:{iv.hex()}
size:{len(data)}
"""

    file = open(meta_path, "w")
    file.write(meta)
    file.close()

    return 1


# Decrypt file
def decrypt_file(username, filename):
    init()

    enc_path = ENCRYPTED_DIR + filename + ".enc"
    meta_path = META_DIR + filename + ".meta"
    out_path = DECRYPTED_DIR + filename + "_dec.txt"

    if not os.path.exists(enc_path):
        return -1

    # read metadata safely
    meta_dict = {}

    file = open(meta_path, "r")
    for line in file:
        if ":" in line:
            k, v = line.strip().split(":", 1)
            meta_dict[k] = v
    file.close()

    key = bytes.fromhex(meta_dict["key"])
    iv = bytes.fromhex(meta_dict["iv"])

    encrypted = open(enc_path, "rb").read()

    decrypted = decrypt(encrypted, key, iv)

    file = open(out_path, "wb")
    file.write(decrypted)
    file.close()

    return 1


# Read decrypted file
def read_file(username, filename):
    path = DECRYPTED_DIR + filename + ".txt"

    if not os.path.exists(path):
        return None

    return open(path, "r").read()