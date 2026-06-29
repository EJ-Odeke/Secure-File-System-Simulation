import re

def is_valid_username(username):
    if not isinstance(username, str):
        return False

    if len(username) < 6 or len(username) >= 32:
        return False

    return re.fullmatch(r'^[A-Za-z0-9]+$', username) is not None


def is_valid_password(password):
    if not isinstance(password, str):
        return False

    if len(password) < 9 or len(password) >= 32:
        return False

    return re.fullmatch(r'^[A-Za-z0-9@#$%&*()\-+=]+$', password) is not None