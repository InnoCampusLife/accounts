import random
import string


def random_string(size=32, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))


def filter_dict_fields(data, exclude_fields, keep_fields=None, **kwargs):
    """
    Filter object and leave only allowed fields.

    :param data: object to be filtered
    :param exclude_fields: field names to be excluded. optional(exclusive with keep_fields)
    :param keep_fields: field names to keep. optional(exclusive with exclude_field)
    :param kwargs: other params
    :return: filtered object
    """

    if data is None:
        return None

    if exclude_fields is None and keep_fields is None:
        return {}

    if keep_fields is not None:
        allowed_fields = keep_fields
    else:
        if 'id' in exclude_fields:
            exclude_fields.append('_id')
            exclude_fields.remove('id')

        allowed_fields = list(filter(lambda fd: fd not in exclude_fields, data.keys()))

    new_obj = {}

    for field in allowed_fields:
        if field in data:
            new_obj[field] = data[field]

    if '_id' in allowed_fields or 'id' in allowed_fields and '_id' in data:
        new_obj['id'] = str(data['_id'])

        if '_id' in new_obj:
            del new_obj['_id']

    return new_obj


def is_function(obj):
    return hasattr(obj, '__call__')