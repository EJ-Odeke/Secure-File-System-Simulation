import os
import hashlib
import binascii

from auth.validator import validate_username, validate_password


ITERATIONS = 20000
SALT_LENGTH = 32


def generate_salt():
    """
    Generate random 32 byte salt
    """

    return os.urandom(SALT_LENGTH)


def hash_password(password, salt):
    """
    SEFS requirement:

    PKCS5_PBKDF2_HMAC_SHA1
    iterations = 20000
    """

    password_bytes = password.encode("utf-8")

    hashed = hashlib.pbkdf2_hmac(
        "sha1",
        password_bytes,
        salt,
        ITERATIONS
    )

    return hashed


def save_user(username, salt, hashed_password, password_file):
    """
    Save user in format:

    username:salt:hashedPassword
    """

    salt_hex = binascii.hexlify(salt).decode()
    hash_hex = binascii.hexlify(hashed_password).decode()

    with open(password_file, "a") as file:
        file.write(
            f"{username}:{salt_hex}:{hash_hex}\n"
        )


def read_users(password_file):
    """
    Read password file
    """

    users = []

    if not os.path.exists(password_file):
        return users

    with open(password_file, "r") as file:

        for line in file:

            line = line.strip()

            if line:

                parts = line.split(":")

                if len(parts) == 3:

                    users.append(parts)

    return users


def register_user(u, p, pFile):
    """
    register_user(u,p,pFile)

    Returns:
    OKAY -> 1
    ERROR -> -1
    """

    if not validate_username(u):
        return -1

    if not validate_password(p):
        return -1


    if is_user_valid(u, pFile):
        return -1


    salt = generate_salt()

    hashed_password = hash_password(
        p,
        salt
    )


    save_user(
        u,
        salt,
        hashed_password,
        pFile
    )


    return 1



def delete_user(u, p, pFile):
    """
    delete_user(u,p,pFile)

    Returns:
    OKAY -> 1
    ERROR -> -1
    """

    if match_user(u, p, pFile) != 1:
        return -1


    users = read_users(pFile)

    updated_users = []


    for user in users:

        if user[0] != u:
            updated_users.append(user)


    with open(pFile, "w") as file:

        for user in updated_users:

            file.write(
                ":".join(user) + "\n"
            )


    return 1



def is_user_valid(u, pFile):
    """
    Check if username exists
    """

    users = read_users(pFile)

    for user in users:

        if user[0] == u:
            return True


    return False



def match_user(u, p, pFile):
    """
    Verify username and password

    Returns:
    OKAY -> 1
    ERROR -> -1
    """

    users = read_users(pFile)


    for user in users:

        username = user[0]
        salt_hex = user[1]
        stored_hash = user[2]


        if username == u:

            salt = binascii.unhexlify(
                salt_hex
            )


            new_hash = hash_password(
                p,
                salt
            )


            new_hash_hex = binascii.hexlify(
                new_hash
            ).decode()


            if new_hash_hex == stored_hash:
                return 1


            return -1


    return -1



def change_user_password(u, p, pn, pFile):
    """
    change_user_password(u,p,pn,pFile)

    Returns:
    OKAY -> 1
    ERROR -> -1
    """

    if match_user(u, p, pFile) != 1:
        return -1


    if not validate_password(pn):
        return -1


    users = read_users(pFile)


    with open(pFile, "w") as file:


        for user in users:


            if user[0] == u:

                salt = generate_salt()

                new_hash = hash_password(
                    pn,
                    salt
                )


                user = [
                    u,
                    binascii.hexlify(salt).decode(),
                    binascii.hexlify(new_hash).decode()
                ]


            file.write(
                ":".join(user) + "\n"
            )


    return 1