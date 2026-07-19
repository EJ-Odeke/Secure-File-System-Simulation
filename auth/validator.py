import re


def validate_username(username):
    """
    SEFS username requirements:
    - Allowed characters: a-zA-Z0-9
    - Length >= 6 and < 32
    """

    if not isinstance(username, str):
        return False

    if len(username) < 6 or len(username) >= 32:
        return False

    pattern = r"^[a-zA-Z0-9]+$"

    return re.match(pattern, username) is not None


def validate_password(password):
    """
    SEFS password requirements:
    - Allowed characters:
      a-zA-Z0-9@#$%&*()-+=
    - Length >= 9 and < 32
    """

    if not isinstance(password, str):
        return False

    if len(password) < 9 or len(password) >= 32:
        return False

    pattern = r"^[a-zA-Z0-9@#$%&*()\-\+=]+$"

    return re.match(pattern, password) is not None