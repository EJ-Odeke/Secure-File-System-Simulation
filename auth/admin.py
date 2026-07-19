import os

from auth.auth import (
    register_user,
    delete_user,
    change_user_password,
    match_user
)


PASSWORD_FILE = "database/passwd"

ADMIN_FILE = "database/admins"



# =====================================================
# INITIALIZE ADMIN FILE
# =====================================================

def initialize_admins():

    os.makedirs(
        "database",
        exist_ok=True
    )


    if not os.path.exists(
        ADMIN_FILE
    ):

        with open(
            ADMIN_FILE,
            "w"
        ) as file:

            file.write(
                ""
            )



# =====================================================
# CHECK ADMIN
# =====================================================

def is_admin(username):

    initialize_admins()


    with open(
        ADMIN_FILE,
        "r"
    ) as file:

        admins = file.read().splitlines()



    return username in admins




# =====================================================
# ADMIN LOGIN CHECK
# =====================================================

def admin_login(
    username,
    password
):

    if match_user(
        username,
        password,
        PASSWORD_FILE
    ) != 1:

        return False


    return is_admin(
        username
    )




# =====================================================
# CREATE USER
# =====================================================

def admin_create_user(
    admin_username,
    username,
    password
):

    if not is_admin(
        admin_username
    ):

        return -1


    return register_user(
        username,
        password,
        PASSWORD_FILE
    )




# =====================================================
# DELETE USER
# =====================================================

def admin_delete_user(
    admin_username,
    username,
    password
):

    if not is_admin(
        admin_username
    ):

        return -1


    return delete_user(
        username,
        password,
        PASSWORD_FILE
    )




# =====================================================
# CHANGE PASSWORD
# =====================================================

def admin_change_password(
    admin_username,
    username,
    old_password,
    new_password
):

    if not is_admin(
        admin_username
    ):

        return -1


    return change_user_password(
        username,
        old_password,
        new_password,
        PASSWORD_FILE
    )