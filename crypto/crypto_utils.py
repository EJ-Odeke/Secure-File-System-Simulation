import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#Cipher : builds encryption system
#algorithms: defines AES
#modes: defines encryption mode (CTR)


def generate_key():
    return secrets.token_bytes(16) # generates 16 random bytes = 128-bit key
                                   # AES supports 128-bit keys (16 bytes) thus secret encryption password


def generate_iv():
    return secrets.token_bytes(16) # IV ensures encryption is non-repetitive and safe


# this is where the real encryption happens

# Create AES encryption engine using CTR mode with this key and IV
#AES(key): means same key used for encrypt + decrypt

def encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    #prepare encryption pipeline
    enc = cipher.encryptor()
    #encrypted bytes (ciphertext)
    return enc.update(data) + enc.finalize()



# fro decryption, you must have the same IV and Key
def decrypt(data, key, iv):
    #Rebuilds SAME encryption system used earlier
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()