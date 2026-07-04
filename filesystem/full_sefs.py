import os
import json
import hashlib
import hmac
import secrets
import base64

from crypto.crypto_utils import encrypt, decrypt

CHUNK_DIR = "storage/chunks/"
DB_FILE = "storage/files.json"



# INIT

def init():
    os.makedirs(CHUNK_DIR, exist_ok=True)

    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump({}, f)



# DB storage

def load_db():
    if not os.path.exists(DB_FILE):
        return {}

    try:
        return json.load(open(DB_FILE))
    except:
        return {}


def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=2)


# Create file
def create_file(u, p, filename, content=""):
    init()
    db = load_db()

    if filename in db:
        return -1

    db[filename] = {
        "owner": u,
        "plaintext": content,
        "chunks": [],
        "security": {},
        "locked": False
    }

    save_db(db)
    return 1


# writting file
def write_to_file(u, p, filename, position, content):
    db = load_db()

    if filename not in db:
        return -1

    db[filename]["plaintext"] = content
    save_db(db)
    return 1


# ENCRYPT FILE

def encrypt_file(u, p, filename):
    init()
    db = load_db()

    if filename not in db:
        return -1

    text = db[filename]["plaintext"]

    if not text:
        return -1

    data = text.encode()

    key = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)

    encrypted = encrypt(data, key, iv)

    cname = f"{filename}.bin"
    cpath = CHUNK_DIR + cname

    with open(cpath, "wb") as f:
        f.write(encrypted)

    mac = hmac.new(key, encrypted, hashlib.sha256).hexdigest()

    db[filename]["chunks"] = [cname]
    db[filename]["security"] = {
        "key": key.hex(),
        "iv": iv.hex(),
        "hmac": mac
    }

    db[filename]["locked"] = True

    save_db(db)

    return {
        "status": "ENCRYPTED",
        "key": key.hex(),
        "iv": iv.hex()
    }


# DECRYPT 

def _decrypt_internal(filename):
    db = load_db()

    
    if not db[filename].get("chunks"):
        return -1

    cname = db[filename]["chunks"][0]
    path = CHUNK_DIR + cname

    if not os.path.exists(path):
        return -1

    encrypted = open(path, "rb").read()

    sec = db[filename]["security"]

    key = bytes.fromhex(sec["key"])
    iv = bytes.fromhex(sec["iv"])

    mac = hmac.new(key, encrypted, hashlib.sha256).hexdigest()

    if mac != sec["hmac"]:
        return -1

    return decrypt(encrypted, key, iv).decode(errors="ignore")


# READ FILE 
def read_from_file(u, p, filename, position=0, length=None):
    db = load_db()

    if filename not in db:
        return -1


    if not db[filename].get("chunks"):
        return "ERROR: FILE NOT ENCRYPTED YET"

    cname = db[filename]["chunks"][0]
    path = CHUNK_DIR + cname

    if not os.path.exists(path):
        return "ERROR: FILE MISSING ON DISK"

    encrypted = open(path, "rb").read()

    if db[filename].get("locked", False):
        preview = base64.b64encode(encrypted).decode()
        return preview[:200] + " ... [ENCRYPTED]"

    return _decrypt_internal(filename)


# DECRYPT WITH KEY + IV

def decrypt_file_with_prompt(u, p, filename, input_key, input_iv):
    db = load_db()

    if filename not in db:
        return -1

    sec = db[filename]["security"]

    if input_key != sec["key"] or input_iv != sec["iv"]:
        return "ERROR: INVALID KEY OR IV"

    text = _decrypt_internal(filename)

    if text == -1:
        return -1

    db[filename]["locked"] = False
    save_db(db)

    return text


# FILE SIZE

def file_size(u, p, filename):
    db = load_db()

    if filename not in db:
        return -1

    return len(db[filename]["plaintext"])


# LIST FILES

def list_files():
    db = load_db()
    return list(db.keys())


# DELETE FILE

def delete_file(u, p, filename):
    db = load_db()

    if filename not in db:
        return -1

    for c in db[filename]["chunks"]:
        path = CHUNK_DIR + c
        if os.path.exists(path):
            os.remove(path)

    del db[filename]
    save_db(db)

    return 1

# INTEGRITY CHECK

def file_integrity_check(u, p, filename):
    db = load_db()

    if filename not in db:
        return -1

    if not db[filename].get("chunks"):
        return -1

    cname = db[filename]["chunks"][0]
    path = CHUNK_DIR + cname

    if not os.path.exists(path):
        return -1

    encrypted = open(path, "rb").read()
    sec = db[filename]["security"]

    key = bytes.fromhex(sec["key"])
    mac = hmac.new(key, encrypted, hashlib.sha256).hexdigest()

    return 1 if mac == sec["hmac"] else -1


# SYSTEM HEALTH
def system_health_check():
    db = load_db()
    return json.dumps(db, indent=2)
