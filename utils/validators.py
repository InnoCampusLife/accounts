import re

MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 16

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 64

MIN_NAME_COMPONENT_LENGTH = 1
MAX_NAME_COMPONENT_LENGTH = 35

MIN_EMAIL_LENGTH = 7
MAX_EMAIL_LENGTH = 255

MIN_STUDY_GROUP_LENGTH = 3
MAX_STUDY_GROUP_LENGTH = 10

MIN_TOKEN_LENGTH = 32
MAX_TOKEN_LENGTH = 128

MIN_ID_LENGTH = 24
MAX_ID_LENGTH = 128

USERNAME_PATTERN = '^\w{%s,%s}$' % (MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH)
NAME_COMPONENT_PATTERN = '^[\w -]{%s,%s}$' % (MIN_NAME_COMPONENT_LENGTH, MAX_NAME_COMPONENT_LENGTH)
EMAIL_PATTERN = '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
STUDY_GROUP_PATTERN = '^[\w#-]{%s,%s}$' % (MIN_STUDY_GROUP_LENGTH, MAX_STUDY_GROUP_LENGTH)
TOKEN_PATTERN = '^\w{%s,%s}$' % (MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH)
ID_PATTERN = '^\w{%s,%s}$' % (MIN_ID_LENGTH, MAX_ID_LENGTH)


def is_username_valid(username):
    username = username.strip()
    return re.match(USERNAME_PATTERN, username, re.IGNORECASE) is not None


def is_password_valid(password):
    return (lambda password_length: MIN_PASSWORD_LENGTH <= password_length <= MAX_PASSWORD_LENGTH)(len(password))


def is_name_component_valid(name_component):
    name_component = name_component.strip()
    return re.match(NAME_COMPONENT_PATTERN, name_component, re.IGNORECASE | re.U) is not None


def is_study_group_valid(study_group):
    study_group = study_group.strip()
    return re.match(STUDY_GROUP_PATTERN, study_group, re.IGNORECASE) is not None


def is_email_valid(email):
    email = email.strip()

    if not (lambda email_length: MIN_EMAIL_LENGTH <= email_length <= MAX_EMAIL_LENGTH)(len(email)):
        return False

    return re.match(EMAIL_PATTERN, email, re.IGNORECASE) is not None


def is_token_valid(token):
    token = token.strip()
    return re.match(TOKEN_PATTERN, token, re.IGNORECASE) is not None


def is_id_valid(id):
    id = id.strip()
    return re.match(ID_PATTERN, id, re.IGNORECASE) is not None
