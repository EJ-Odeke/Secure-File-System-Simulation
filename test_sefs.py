from auth.auth import (
    register_user,
    match_user
)

from filesystem.sefs import (
    create_file,
    encrypt_file,
    decrypt_file,
    read_from_file,
    write_to_file,
    delete_file,
    file_size,
    file_integrity_check,
    system_health_check
)


PASSWORD_FILE = "database/passwd"

USERNAME = "elijah1"
PASSWORD = "Password123@"


TEST_FILE = "secret.txt"



print("\n--- USER LOGIN ---")

print(
    match_user(
        USERNAME,
        PASSWORD,
        PASSWORD_FILE
    )
)



print("\n--- CREATE PLAINTEXT FILE ---")

with open(
    TEST_FILE,
    "w"
) as file:

    file.write(
        "This is a Secure File System test file."
    )


print("Created")



print("\n--- ENCRYPT FILE ---")

print(
    encrypt_file(
        USERNAME,
        PASSWORD,
        TEST_FILE
    )
)



print("\n--- FILE SIZE ---")

print(
    file_size(
        USERNAME,
        PASSWORD,
        TEST_FILE
    )
)



print("\n--- READ FILE ---")

print(
    read_from_file(
        USERNAME,
        PASSWORD,
        TEST_FILE,
        0,
        20
    )
)



print("\n--- WRITE FILE ---")

print(
    write_to_file(
        USERNAME,
        PASSWORD,
        TEST_FILE,
        0,
        b"UPDATED DATA "
    )
)



print("\n--- READ AFTER WRITE ---")

print(
    read_from_file(
        USERNAME,
        PASSWORD,
        TEST_FILE,
        0,
        30
    )
)



print("\n--- DECRYPT FILE ---")

print(
    decrypt_file(
        USERNAME,
        PASSWORD,
        TEST_FILE,
        "decrypted.txt"
    )
)



print("\n--- INTEGRITY CHECK ---")

print(
    file_integrity_check(
        USERNAME,
        PASSWORD,
        TEST_FILE
    )
)



print("\n--- SYSTEM HEALTH ---")

print(
    system_health_check()
)



print("\n--- DELETE FILE ---")

print(
    delete_file(
        USERNAME,
        PASSWORD,
        TEST_FILE
    )
)