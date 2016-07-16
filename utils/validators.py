import re

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 32

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 64

USERNAME_PATTERN = '^\w{%s,%s}$' % (MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH)


def is_username_valid(username):
    return re.match(USERNAME_PATTERN, username, re.IGNORECASE) is not None


def is_password_valid(password):
    return (lambda password_length: MIN_PASSWORD_LENGTH <= password_length <= MAX_PASSWORD_LENGTH)(len(password))

