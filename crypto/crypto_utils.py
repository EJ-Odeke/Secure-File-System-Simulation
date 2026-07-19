import os
import hashlib
import hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# SEFS requirements

KEY_SIZE = 16       # 128 bits
IV_SIZE = 16        # 128 bits



# =====================================================
# KEY AND IV GENERATION
# =====================================================

def generate_key():
    """
    Generate random 128-bit AES key
    """

    return os.urandom(KEY_SIZE)



def generate_iv():
    """
    Generate random 128-bit IV
    """

    return os.urandom(IV_SIZE)



# =====================================================
# AES CTR ENCRYPTION / DECRYPTION
# =====================================================

def encrypt_aes_ctr(plaintext, key, iv):
    """
    AES CTR encryption

    plaintext: bytes
    key: 128-bit key
    iv: 128-bit IV

    returns encrypted bytes
    """

    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv)
    )


    encryptor = cipher.encryptor()


    ciphertext = encryptor.update(
        plaintext
    ) + encryptor.finalize()


    return ciphertext



def decrypt_aes_ctr(ciphertext, key, iv):
    """
    AES CTR decryption

    Since CTR mode is symmetric,
    encryption and decryption are identical.
    """

    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv)
    )


    decryptor = cipher.decryptor()


    plaintext = decryptor.update(
        ciphertext
    ) + decryptor.finalize()


    return plaintext



# =====================================================
# SHA256 DIGEST
# =====================================================

def sha256_digest(data):
    """
    SHA256 hash

    Used for:
    - Master file list
    - Integrity checking
    """

    return hashlib.sha256(data).hexdigest()



def sha256_file(filename):
    """
    SHA256 digest of a file
    """

    sha256 = hashlib.sha256()


    with open(filename, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)


    return sha256.hexdigest()



# =====================================================
# HMAC SHA256
# =====================================================

def generate_hmac(data, key):
    """
    HMAC using SHA256

    SEFS requirement:
    HMAC + EVP_sha256()
    """

    return hmac.new(
        key,
        data,
        hashlib.sha256
    ).hexdigest()



def verify_hmac(data, key, received_hmac):
    """
    Verify chunk integrity
    """

    calculated_hmac = generate_hmac(
        data,
        key
    )


    return hmac.compare_digest(
        calculated_hmac,
        received_hmac
    )



# =====================================================
# MASTER KEY FILE HANDLING
# =====================================================

def save_master_key(master_key, master_iv, filename):
    """
    Save master key and IV

    Stored as binary:
    key + IV
    """

    with open(filename, "wb") as file:

        file.write(master_key)

        file.write(master_iv)



def load_master_key(filename):
    """
    Load master key and IV
    """

    with open(filename, "rb") as file:

        master_key = file.read(KEY_SIZE)

        master_iv = file.read(IV_SIZE)


    return master_key, master_iv



# =====================================================
# TEST FUNCTION
# =====================================================

def test_crypto():

    key = generate_key()

    iv = generate_iv()


    message = b"Secure File System Test"


    encrypted = encrypt_aes_ctr(
        message,
        key,
        iv
    )


    decrypted = decrypt_aes_ctr(
        encrypted,
        key,
        iv
    )


    print("Original:")
    print(message)


    print("\nEncrypted:")
    print(encrypted)


    print("\nDecrypted:")
    print(decrypted)



if __name__ == "__main__":

    test_crypto()