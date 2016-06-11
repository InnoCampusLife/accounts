import string
import random

from flask_restful import marshal


def random_string(size=32, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def exclude_fields(data, exclude_fields, **kwargs):
    allowed_fields = list(filter(lambda fd: fd not in exclude_fields, data.keys()))
    new_obj = {}

    for field in allowed_fields:
        new_obj[field] = data[field]

    return new_obj


def is_function(obj):
    return hasattr(obj, '__call__')
