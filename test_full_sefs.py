from filesystem.full_sefs import (
    encrypt_file,
    read_from_file,
    file_size,
    file_integrity_check,
    delete_file
)


USERNAME = "elijah1"
PASSWORD = "Password123@"


FILE = "large_test.txt"


print("\n--- FULL SEFS ENCRYPTION ---")

result = encrypt_file(
    USERNAME,
    PASSWORD,
    FILE
)

print(
    "Encrypt:",
    result
)



print("\n--- FILE SIZE ---")

size = file_size(
    USERNAME,
    PASSWORD,
    FILE
)

print(
    "Size:",
    size
)



print("\n--- READ FULL FILE ---")

data = read_from_file(
    USERNAME,
    PASSWORD,
    FILE
)

if data:

    print(
        "Read successful"
    )

    print(
        "First 100 characters:"
    )

    print(
        data[:100]
    )


else:

    print(
        "Read failed"
    )



print("\n--- INTEGRITY CHECK ---")

print(
    file_integrity_check(
        USERNAME,
        PASSWORD,
        FILE
    )
)



print("\n--- DELETE TEST ---")

print(
    delete_file(
        USERNAME,
        PASSWORD,
        FILE
    )
)