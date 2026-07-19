import os
import json
import pickle
import random
import string

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
# CONFIGURATION
# =====================================================

CHUNK_SIZE = 1024

STORAGE_DIR = "storage/full"

META_DIR = os.path.join(
    STORAGE_DIR,
    "meta"
)

CHUNK_DIR = os.path.join(
    STORAGE_DIR,
    "chunks"
)

MASTER_LIST = os.path.join(
    STORAGE_DIR,
    "master_file_list.json"
)

PASSWORD_FILE = "database/passwd"



# =====================================================
# INITIALIZATION
# =====================================================

def initialize():

    os.makedirs(
        META_DIR,
        exist_ok=True
    )

    os.makedirs(
        CHUNK_DIR,
        exist_ok=True
    )


    if not os.path.exists(MASTER_LIST):

        with open(
            MASTER_LIST,
            "w"
        ) as file:

            json.dump(
                {},
                file
            )



# =====================================================
# AUTHENTICATION
# =====================================================

def authenticate(u, p):

    return match_user(
        u,
        p,
        PASSWORD_FILE
    ) == 1



# =====================================================
# OWNER CHECK
# =====================================================

def check_file_owner(
    u,
    filename
):

    meta_path = os.path.join(
        META_DIR,
        filename + ".meta"
    )


    if not os.path.exists(meta_path):

        return False


    with open(
        meta_path,
        "rb"
    ) as file:

        meta = pickle.load(file)


    return meta.get("owner") == u




# =====================================================
# HELPERS
# =====================================================

def generate_chunk_name():

    chars = (
        string.ascii_letters +
        string.digits
    )


    return "".join(
        random.choice(chars)
        for _ in range(16)
    )



def load_master():

    initialize()


    with open(
        MASTER_LIST,
        "r"
    ) as file:

        return json.load(file)



def save_master(data):

    with open(
        MASTER_LIST,
        "w"
    ) as file:

        json.dump(
            data,
            file,
            indent=4
        )



def split_chunks(data):

    chunks = []


    for index in range(
        0,
        len(data),
        CHUNK_SIZE
    ):

        chunks.append(
            data[index:index + CHUNK_SIZE]
        )


    if len(chunks) == 0:

        chunks.append(
            b""
        )


    if len(chunks[-1]) < CHUNK_SIZE:

        chunks[-1] += (
            b"0" *
            (
                CHUNK_SIZE -
                len(chunks[-1])
            )
        )


    return chunks




# =====================================================
# CREATE FILE
# =====================================================

def create_file(
    u,
    p,
    filename
):

    if not authenticate(
        u,
        p
    ):

        return -1


    initialize()


    meta_path = os.path.join(
        META_DIR,
        filename + ".meta"
    )


    if os.path.exists(meta_path):

        return -1



    meta = {

        "owner": u,

        "file_size": 0,

        "number_of_chunks": 0,

        "start_chunk": None,

        "end_chunk": None

    }



    with open(
        meta_path,
        "wb"
    ) as file:

        pickle.dump(
            meta,
            file
        )



    master = load_master()



    master[filename] = sha256_file(
        meta_path
    )



    save_master(
        master
    )


    return 1

# =====================================================
# ENCRYPT FILE
# =====================================================

def encrypt_file(
    u,
    p,
    filename
):

    if not authenticate(
        u,
        p
    ):

        return -1



    if not os.path.exists(filename):

        return -1



    initialize()



    with open(
        filename,
        "rb"
    ) as file:

        plaintext = file.read()



    chunks = split_chunks(
        plaintext
    )


    chunk_names = []


    previous_chunk = None



    for content in chunks:


        chunk_name = generate_chunk_name()


        key = generate_key()

        iv = generate_iv()



        encrypted = encrypt_aes_ctr(
            content,
            key,
            iv
        )



        chunk = {

            "name": chunk_name,

            "key": key.hex(),

            "iv": iv.hex(),

            "hmac": generate_hmac(
                encrypted,
                key
            ),

            "next_chunk": None,

            "content": encrypted.hex()

        }



        if previous_chunk:


            previous_chunk["next_chunk"] = chunk_name


            with open(
                os.path.join(
                    CHUNK_DIR,
                    previous_chunk["name"]
                ),
                "wb"
            ) as file:

                pickle.dump(
                    previous_chunk,
                    file
                )



        with open(
            os.path.join(
                CHUNK_DIR,
                chunk_name
            ),
            "wb"
        ) as file:

            pickle.dump(
                chunk,
                file
            )



        previous_chunk = chunk


        chunk_names.append(
            chunk_name
        )



    meta = {

        "owner": u,

        "file_size": len(plaintext),

        "number_of_chunks": len(chunk_names),

        "start_chunk": chunk_names[0],

        "end_chunk": chunk_names[-1]

    }



    meta_path = os.path.join(
        META_DIR,
        filename + ".meta"
    )



    with open(
        meta_path,
        "wb"
    ) as file:

        pickle.dump(
            meta,
            file
        )



    master = load_master()



    master[filename] = sha256_file(
        meta_path
    )



    save_master(
        master
    )


    return 1





# =====================================================
# DECRYPT FILE
# =====================================================

def decrypt_file(
    u,
    p,
    filename,
    pfilename
):


    if not authenticate(
        u,
        p
    ):

        return -1



    if not check_file_owner(
        u,
        filename
    ):

        return -1



    size = file_size(
        u,
        p,
        filename
    )



    if size == -1:

        return -1



    data = read_from_file(
        u,
        p,
        filename,
        0,
        size
    )



    if data is None:

        return -1



    with open(
        pfilename,
        "wb"
    ) as file:

        file.write(
            data
        )


    return 1





# =====================================================
# READ FILE
# =====================================================

def read_from_file(
    u,
    p,
    filename,
    position,
    length
):


    if not authenticate(
        u,
        p
    ):

        return None



    if not check_file_owner(
        u,
        filename
    ):

        return None



    meta_path = os.path.join(
        META_DIR,
        filename + ".meta"
    )



    if not os.path.exists(meta_path):

        return None



    with open(
        meta_path,
        "rb"
    ) as file:

        meta = pickle.load(file)



    result = b""


    current = meta["start_chunk"]



    while current:


        with open(
            os.path.join(
                CHUNK_DIR,
                current
            ),
            "rb"
        ) as file:

            chunk = pickle.load(file)



        key = bytes.fromhex(
            chunk["key"]
        )


        iv = bytes.fromhex(
            chunk["iv"]
        )


        encrypted = bytes.fromhex(
            chunk["content"]
        )



        if not verify_hmac(
            encrypted,
            key,
            chunk["hmac"]
        ):

            return None



        result += decrypt_aes_ctr(
            encrypted,
            key,
            iv
        )



        current = chunk["next_chunk"]



    result = result[:meta["file_size"]]



    return result[
        position:
        position + length
    ]





# =====================================================
# WRITE FILE
# =====================================================

def write_to_file(
    u,
    p,
    filename,
    position,
    newcontent
):


    if not authenticate(
        u,
        p
    ):

        return -1



    if not check_file_owner(
        u,
        filename
    ):

        return -1



    current_size = file_size(
        u,
        p,
        filename
    )



    if current_size == -1:

        return -1



    with open(
        "__temp_original",
        "wb"
    ) as file:

        file.write(
            read_from_file(
                u,
                p,
                filename,
                0,
                current_size
            )
        )



    with open(
        "__temp_original",
        "rb"
    ) as file:

        data = file.read()



    if position > len(data):

        return -1



    updated = (

        data[:position]

        +

        newcontent

        +

        data[
            position + len(newcontent):
        ]

    )



    delete_file(
        u,
        p,
        filename
    )



    with open(
        "__temp_write",
        "wb"
    ) as file:

        file.write(
            updated
        )



    result = encrypt_file(
        u,
        p,
        "__temp_write"
    )

    old_meta = os.path.join(
        META_DIR,
        "__temp_write.meta"
    )

    new_meta = os.path.join(
        META_DIR,
        filename + ".meta"
    )

    if os.path.exists(old_meta):
        os.rename(
            old_meta,
            new_meta
        )

    master = load_master()

    if "__temp_write" in master:
        master[filename] = master.pop(
            "__temp_write"
        )

        save_master(
            master
        )

    if os.path.exists(
            "__temp_original"
    ):
        os.remove(
            "__temp_original"
        )

    if os.path.exists(
            "__temp_write"
    ):
        os.remove(
            "__temp_write"
        )

    return result


# =====================================================
# FILE SIZE
# =====================================================

def file_size(
        u,
        p,
        filename
):
    if not authenticate(
            u,
            p
    ):
        return -1

    if not check_file_owner(
            u,
            filename
    ):
        return -1

    meta_path = os.path.join(
        META_DIR,
        filename + ".meta"
    )

    if not os.path.exists(meta_path):
        return -1

    with open(
            meta_path,
            "rb"
    ) as file:

        meta = pickle.load(file)

    return meta["file_size"]


# =====================================================
# DELETE FILE
# =====================================================

def delete_file(
        u,
        p,
        filename
):
    if not authenticate(
            u,
            p
    ):
        return -1

    if not check_file_owner(
            u,
            filename
    ):
        return -1

    meta_path = os.path.join(
        META_DIR,
        filename + ".meta"
    )

    if not os.path.exists(meta_path):
        return -1

    with open(
            meta_path,
            "rb"
    ) as file:

        meta = pickle.load(file)

    current = meta["start_chunk"]

    while current:

        chunk_path = os.path.join(
            CHUNK_DIR,
            current
        )

        if not os.path.exists(chunk_path):
            break

        with open(
                chunk_path,
                "rb"
        ) as file:

            chunk = pickle.load(file)

        next_chunk = chunk["next_chunk"]

        os.remove(
            chunk_path
        )

        current = next_chunk

    os.remove(
        meta_path
    )

    master = load_master()

    if filename in master:
        del master[filename]

        save_master(
            master
        )

    return 1


# =====================================================
# FILE INTEGRITY CHECK
# =====================================================

def file_integrity_check(
        u,
        p,
        filename
):
    if not authenticate(
            u,
            p
    ):
        return -1

    if not check_file_owner(
            u,
            filename
    ):
        return -1

    meta_path = os.path.join(
        META_DIR,
        filename + ".meta"
    )

    if not os.path.exists(meta_path):
        return -1

    master = load_master()

    current_hash = sha256_file(
        meta_path
    )

    if master.get(filename) != current_hash:
        return -1

    return 1


# =====================================================
# SYSTEM HEALTH CHECK
# =====================================================

def system_health_check():
    try:

        initialize()

        required = [

            META_DIR,

            CHUNK_DIR,

            MASTER_LIST

        ]

        for item in required:

            if not os.path.exists(item):
                return None

        return "SEFS SYSTEM HEALTHY"



    except Exception:

        return None