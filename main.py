from auth.auth import register_user, match_user
from filesystem.full_sefs import (
    create_file,
    write_to_file,
    encrypt_file,
    decrypt_file_with_prompt,
    read_from_file,
    delete_file,
    list_files,
    file_size,
    file_integrity_check,
    system_health_check
)

PFILE = "database/passwd" # is where user credentials are stored
current_user = None # tracks logged in user session


# display menu

def auth_menu():
    print("\n1. Sign Up")
    print("2. Login")
    print("3. Exit")
    return input("Choose: ")



## singup -paged- this code hANDLES signups

def signup():
    u = input("Username: ")
    p = input("Password: ")
    # username + password stored in file (database/passwd)
    print("✔" if register_user(u, p, PFILE) == 1 else "✖")



# LOGIN
def login():
    global current_user

    u = input("Username: ")
    p = input("Password: ")

    if match_user(u, p, PFILE):
        current_user = u
        print("✔ Login successful")
        return True

    print("✖ Login failed")
    return False



# File management menu or main dashboard after login

def file_menu(): # this is the core engine of this App
    print("\n===== Secure File System Simulation MENU =====")
    print("1. Create File")
    print("2. Encrypt File")
    print("3. Decrypt File (Key + IV)")
    print("4. Read File")
    # write not yet activated
    print("5. List Files")
    print("6. Delete File")
    print("7. File Size")
    print("8. Integrity Check")
    print("9. System Health")
    print("10. Logout")
    return input("Choose: ")



# File system script

def file_system():
    global current_user

    while True:

        choice = file_menu()

        if choice == "1":
            n = input("File name: ")
            c = input("Content: ")
            print(create_file(current_user, None, n, c))

        elif choice == "2":
            n = input("File name: ")
            print(encrypt_file(current_user, None, n))

        elif choice == "3":
            n = input("File name: ")
            key = input("Enter key (hex): ")
            iv = input("Enter iv (hex): ")
            print(decrypt_file_with_prompt(current_user, None, n, key, iv))

        elif choice == "4":
            n = input("File name: ")
            print(read_from_file(current_user, None, n))

        elif choice == "5":
            print(list_files()) # shows all files belonging to user --still making sure it appears to only current user

        elif choice == "6":
            n = input("File name: ")
            print(delete_file(current_user, None, n)) # removes file permanently

        elif choice == "7":
            n = input("File name: ")
            print(file_size(current_user, None, n)) # returns file size in bytes

        elif choice == "8":
            n = input("File name: ")
            print(file_integrity_check(current_user, None, n)) # checks hash (SHA256 / HMAC)

        elif choice == "9":
            print(system_health_check()) # system status logs

        elif choice == "10":
            current_user = None
            break



# looper --

def main():

    while True:

        if current_user is None:

            c = auth_menu()

            if c == "1":
                signup()

            elif c == "2":
                if login():
                    file_system()

            elif c == "3":
                break


if __name__ == "__main__":
    main()