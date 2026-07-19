from filesystem.full_sefs import (

    create_file,
    encrypt_file,
    decrypt_file,
    read_from_file,
    write_to_file,
    file_size,
    file_integrity_check,
    system_health_check,
    delete_file

)



USERNAME = "elijah1"

PASSWORD = "Password123@"


PLAINTEXT_FILE = "test_document.txt"

SEFS_FILE = "test_document.txt"

DECRYPTED_FILE = "recovered_document.txt"



print("\n==============================")
print("CREATE TEST FILE")
print("==============================")

with open(
    PLAINTEXT_FILE,
    "w"
) as file:

    file.write(
        "This is a test document for SEFS encryption. "
        "This file should be encrypted, stored as chunks, "
        "read, modified and decrypted successfully."
    )


print("Plaintext created")



print("\n==============================")
print("CREATE FILE")
print("==============================")


print(
    create_file(
        USERNAME,
        PASSWORD,
        SEFS_FILE
    )
)



print("\n==============================")
print("ENCRYPT FILE")
print("==============================")


print(
    encrypt_file(
        USERNAME,
        PASSWORD,
        PLAINTEXT_FILE
    )
)



print("\n==============================")
print("FILE SIZE")
print("==============================")


print(
    file_size(
        USERNAME,
        PASSWORD,
        SEFS_FILE
    )
)



print("\n==============================")
print("READ FILE")
print("==============================")


data = read_from_file(
    USERNAME,
    PASSWORD,
    SEFS_FILE,
    0,
    50
)


print(data)



print("\n==============================")
print("WRITE FILE")
print("==============================")


print(
    write_to_file(
        USERNAME,
        PASSWORD,
        SEFS_FILE,
        0,
        b"UPDATED SEFS "
    )
)



print("\n==============================")
print("READ AFTER WRITE")
print("==============================")


data = read_from_file(
    USERNAME,
    PASSWORD,
    SEFS_FILE,
    0,
    80
)


print(data)



print("\n==============================")
print("DECRYPT FILE")
print("==============================")


print(
    decrypt_file(
        USERNAME,
        PASSWORD,
        SEFS_FILE,
        DECRYPTED_FILE
    )
)



print("\n==============================")
print("INTEGRITY CHECK")
print("==============================")


print(
    file_integrity_check(
        USERNAME,
        PASSWORD,
        SEFS_FILE
    )
)



print("\n==============================")
print("SYSTEM HEALTH")
print("==============================")


print(
    system_health_check()
)



print("\n==============================")
print("DELETE FILE")
print("==============================")


print(
    delete_file(
        USERNAME,
        PASSWORD,
        SEFS_FILE
    )
)

