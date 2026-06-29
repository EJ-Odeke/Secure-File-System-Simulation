import os
import hashlib
import binascii
import secrets
import auth.validator as validator


def load_users(pfile):
    users = {}

    if not os.path.exists(pfile):
        return users

    with open(pfile, "r") as f:
        for line in f:
            line = line.strip()
            if ":" not in line:
                continue

            parts = line.split(":")
            if len(parts) != 3:
                continue

            users[parts[0]] = (parts[1], parts[2])

    return users


def save_users(users, pfile):
    with open(pfile, "w") as f:
        for u, (salt, h) in users.items():
            f.write(f"{u}:{salt}:{h}\n")


def hash_password(password, salt):
    dk = hashlib.pbkdf2_hmac(
        "sha1",
        password.encode(),
        salt.encode(),
        20000
    )
    return binascii.hexlify(dk).decode()


def register_user(u, p, pfile):

    if not validator.is_valid_username(u):
        return -1

    if not validator.is_valid_password(p):
        return -1

    users = load_users(pfile)

    if u in users:
        return -1

    salt = secrets.token_hex(32)
    users[u] = (salt, hash_password(p, salt))

    save_users(users, pfile)
    return 1


def match_user(u, p, pfile):
    users = load_users(pfile)

    if u not in users:
        return False

    salt, stored = users[u]
    return hash_password(p, salt) == stored


def delete_user(u, p, pfile):
    users = load_users(pfile)

    if u not in users:
        return -1

    if not match_user(u, p, pfile):
        return -1

    del users[u]
    save_users(users, pfile)
    return 1


def change_user_password(u, p, pn, pfile):
    users = load_users(pfile)

    if u not in users:
        return -1

    if not match_user(u, p, pfile):
        return -1

    if not validator.is_valid_password(pn):
        return -1

    salt = secrets.token_hex(32)
    users[u] = (salt, hash_password(pn, salt))

    save_users(users, pfile)
    return 1


def is_user_valid(u, pfile):
    return u in load_users(pfile)