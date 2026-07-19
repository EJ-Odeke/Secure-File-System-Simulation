import os
import json
import string
import random
import pickle

from auth.auth import match_user

from crypto.crypto_utils import (
    generate_key,
    generate_iv,
    encrypt_aes_ctr,
    decrypt_aes_ctr,
    generate_hmac,
    verify_hmac,
    sha256_file
)


# =====================================================
# PATHS
# =====================================================

STORAGE_DIR = "storage"

META_DIR = os.path.join(
    STORAGE_DIR,
    "meta"
)

CHUNK_DIR = os.path.join(
    STORAGE_DIR,
    "chunks"
)

MASTER_FILE_LIST = os.path.join(
    STORAGE_DIR,
    "master_file_list.json"
)


# =====================================================
# INITIALIZATION
# =====================================================

def initialize_storage():

    os.makedirs(
        META_DIR,
        exist_ok=True
    )

    os.makedirs(
        CHUNK_DIR,
        exist_ok=True
    )


    if not os.path.exists(MASTER_FILE_LIST):

        with open(
            MASTER_FILE_LIST,
            "w"
        ) as file:

            json.dump(
                {},
                file
            )



# =====================================================
# HELPERS
# =====================================================

def generate_chunk_name():

    characters = (
        string.ascii_letters +
        string.digits
    )

    return "".join(
        random.choice(characters)
        for _ in range(12)
    )



def load_master_list():

    initialize_storage()

    with open(
        MASTER_FILE_LIST,
        "r"
    ) as file:

        return json.load(file)



def save_master_list(data):

    with open(
        MASTER_FILE_LIST,
        "w"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )



def authenticate(username,password):

    return match_user(
        username,
        password,
        "database/passwd"
    ) == 1



# =====================================================
# CREATE FILE
# =====================================================

def create_file(u,p,filename):

    if not authenticate(u,p):
        return -1


    initialize_storage()


    meta_file = os.path.join(
        META_DIR,
        filename + ".meta"
    )


    if os.path.exists(meta_file):
        return -1



    chunk_name = generate_chunk_name()

    chunk_key = generate_key()

    chunk_iv = generate_iv()


    empty_content = b""


    encrypted = encrypt_aes_ctr(
        empty_content,
        chunk_key,
        chunk_iv
    )


    chunk_hmac = generate_hmac(
        encrypted,
        chunk_key
    )


    chunk_data = {

        "name": chunk_name,

        "key": chunk_key.hex(),

        "iv": chunk_iv.hex(),

        "hmac": chunk_hmac,

        "content": encrypted.hex()
    }



    with open(
        os.path.join(
            CHUNK_DIR,
            chunk_name
        ),
        "wb"
    ) as file:

        pickle.dump(
            chunk_data,
            file
        )



    meta_data = {


        "owner": u,

        "iv": chunk_iv.hex(),

        "number_of_chunks": 1,

        "next_chunk": None,

        "file_size": 0,

        "chunk_size":0,

        "start_chunk":chunk_name,

        "end_chunk":chunk_name

    }



    with open(
        meta_file,
        "wb"
    ) as file:

        pickle.dump(
            meta_data,
            file
        )



    master = load_master_list()


    master[filename] = sha256_file(
        meta_file
    )


    save_master_list(
        master
    )


    return 1



# =====================================================
# DELETE FILE
# =====================================================

def delete_file(u,p,filename):

    if not authenticate(u,p):
        return -1


    meta_file = os.path.join(
        META_DIR,
        filename+".meta"
    )


    if not os.path.exists(meta_file):
        return -1



    with open(
        meta_file,
        "rb"
    ) as file:

        meta = pickle.load(file)



    chunk = meta["start_chunk"]


    while chunk:

        chunk_path = os.path.join(
            CHUNK_DIR,
            chunk
        )


        next_chunk=None


        if os.path.exists(chunk_path):

            with open(
                chunk_path,
                "rb"
            ) as file:

                data=pickle.load(file)

                next_chunk=data.get(
                    "next_chunk"
                )


            os.remove(
                chunk_path
            )


        chunk=next_chunk



    os.remove(meta_file)



    master=load_master_list()


    if filename in master:

        del master[filename]


    save_master_list(
        master
    )


    return 1



# =====================================================
# ENCRYPT FILE
# =====================================================

def encrypt_file(u,p,filename):

    if not authenticate(u,p):
        return -1


    if not os.path.exists(filename):
        return -1


    with open(
        filename,
        "rb"
    ) as file:

        data=file.read()



    if create_file(
        u,
        p,
        os.path.basename(filename)
    ) != 1:

        return -1



    meta_file=os.path.join(
        META_DIR,
        os.path.basename(filename)+".meta"
    )



    with open(
        meta_file,
        "rb"
    ) as file:

        meta=pickle.load(file)



    chunk=meta["start_chunk"]


    chunk_path=os.path.join(
        CHUNK_DIR,
        chunk
    )



    with open(
        chunk_path,
        "rb"
    ) as file:

        chunk_data=pickle.load(file)



    key=bytes.fromhex(
        chunk_data["key"]
    )

    iv=bytes.fromhex(
        chunk_data["iv"]
    )



    encrypted=encrypt_aes_ctr(
        data,
        key,
        iv
    )



    chunk_data["content"]=encrypted.hex()

    chunk_data["hmac"]=generate_hmac(
        encrypted,
        key
    )



    with open(
        chunk_path,
        "wb"
    ) as file:

        pickle.dump(
            chunk_data,
            file
        )



    meta["file_size"]=len(data)

    meta["chunk_size"]=len(data)



    with open(
        meta_file,
        "wb"
    ) as file:

        pickle.dump(
            meta,
            file
        )


    return 1



# =====================================================
# DECRYPT FILE
# =====================================================

def decrypt_file(u,p,filename,pfilename):

    if not authenticate(u,p):
        return -1


    meta_file=os.path.join(
        META_DIR,
        filename+".meta"
    )


    if not os.path.exists(meta_file):
        return -1



    with open(
        meta_file,
        "rb"
    ) as file:

        meta=pickle.load(file)



    chunk_path=os.path.join(
        CHUNK_DIR,
        meta["start_chunk"]
    )



    with open(
        chunk_path,
        "rb"
    ) as file:

        chunk=pickle.load(file)



    key=bytes.fromhex(
        chunk["key"]
    )

    iv=bytes.fromhex(
        chunk["iv"]
    )


    encrypted=bytes.fromhex(
        chunk["content"]
    )


    decrypted=decrypt_aes_ctr(
        encrypted,
        key,
        iv
    )


    with open(
        pfilename,
        "wb"
    ) as file:

        file.write(
            decrypted
        )


    return 1



# =====================================================
# READ FILE
# =====================================================

def read_from_file(u,p,filename,position,length):

    if not authenticate(u,p):
        return None


    temp="temp_decrypted"


    if decrypt_file(
        u,
        p,
        filename,
        temp
    ) != 1:

        return None



    with open(
        temp,
        "rb"
    ) as file:

        data=file.read()



    os.remove(temp)


    return data[position:position+length]



# =====================================================
# WRITE FILE
# =====================================================

def write_to_file(u,p,filename,position,newcontent):

    if not authenticate(u,p):
        return -1


    temp="temp_write"


    decrypt_file(
        u,
        p,
        filename,
        temp
    )


    with open(
        temp,
        "rb"
    ) as file:

        data=file.read()



    data = (
        data[:position]
        +
        newcontent
        +
        data[position+len(newcontent):]
    )


    with open(
        temp,
        "wb"
    ) as file:

        file.write(data)



    result=encrypt_file(
        u,
        p,
        temp
    )


    os.remove(temp)


    return result



# =====================================================
# FILE SIZE
# =====================================================

def file_size(u,p,filename):

    if not authenticate(u,p):
        return -1


    meta_file=os.path.join(
        META_DIR,
        filename+".meta"
    )


    with open(
        meta_file,
        "rb"
    ) as file:

        meta=pickle.load(file)


    return meta["file_size"]



# =====================================================
# INTEGRITY CHECK
# =====================================================

def file_integrity_check(u,p,filename):

    if not authenticate(u,p):
        return -1


    meta_file=os.path.join(
        META_DIR,
        filename+".meta"
    )


    master=load_master_list()


    if filename not in master:
        return -1



    current=sha256_file(
        meta_file
    )


    if current != master[filename]:

        return -1



    return 1



# =====================================================
# SYSTEM HEALTH CHECK
# =====================================================

def system_health_check():

    try:

        initialize_storage()

        return "SEFS SYSTEM HEALTHY"


    except:

        return None