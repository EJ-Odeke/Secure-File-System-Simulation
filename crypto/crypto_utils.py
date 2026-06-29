import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generate_key():
    return secrets.token_bytes(16)


def generate_iv():
    return secrets.token_bytes(16)


def encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()


def decrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()