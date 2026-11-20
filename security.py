import re


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def validate_registration(
    username: str,
    email: str,
    password: str,
    confirm_password: str,
) -> dict[str, str]:
    errors = {}

    if not username:
        errors["username"] = "Username is required."
    elif not USERNAME_PATTERN.fullmatch(username):
        errors["username"] = "Use 3–30 letters, numbers, or underscores."

    if not email:
        errors["email"] = "Email is required."
    else:
        local_part = email.split("@", 1)[0]
        if (
            len(email) > 254
            or len(local_part) > 64
            or local_part.startswith(".")
            or local_part.endswith(".")
            or ".." in local_part
            or not EMAIL_PATTERN.fullmatch(email)
        ):
            errors["email"] = "Enter a valid email address."

    if not password:
        errors["password"] = "Password is required."
    else:
        try:
            password_bytes = password.encode("utf-8")
        except UnicodeEncodeError:
            errors["password"] = "Password contains unsupported characters."
        else:
            if len(password_bytes) > 72:
                errors["password"] = "Password must not exceed 72 UTF-8 bytes."
            elif (
                len(password) < 8
                or not any(character.isupper() for character in password)
                or not any(character.islower() for character in password)
                or not any(character.isdigit() for character in password)
                or not any(not character.isalnum() for character in password)
            ):
                errors["password"] = (
                    "Use at least 8 characters, including uppercase and lowercase "
                    "letters, a number, and a special character."
                )

    if not confirm_password:
        errors["confirm_password"] = "Please confirm your password."
    elif password != confirm_password:
        errors["confirm_password"] = "Passwords do not match."

    return errors