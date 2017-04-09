import json
import logging
import random
import re

import flask
from bson.objectid import ObjectId

from utils.validators import is_username_valid, is_token_valid, is_id_valid

# result formation

SERVER_NAMES = ['Porky Pig',
                'Piggy (Merrie Melodies)',
                'Playboy Penguin',
                'Spike the Bulldog and Chester the Terrier',
                'Sylvester Jr.',
                'Sylvester the Cat',
                'Gabby Goat',
                'Speedy Gonzales',
                'Foxy (Merrie Melodies)',
                'Michigan J. Frog',
                'Hector the Bulldog',
                'Nasty Canasta',
                'Claude Cat',
                'Merlin the Magic Mouse',
                'Miss Prissy']


def RESULT(status, result, code, error):
    out = {'status': status}

    if result is not None:
        out['result'] = result

    if error is not None:
        out['error'] = error

    resp = flask.Response(response=json.dumps(out), status=code, mimetype='application/json',
                          content_type='application/json')

    resp.headers['Server'] = random.choice(SERVER_NAMES)

    return resp


def RESULT_OK(result=None, code=200):
    return RESULT('ok', result, code, None)


def RESULT_OK_CREATED(result=None, code=201):
    return RESULT('ok', result, code, None)


def RESULT_FAIL_ON_CLIENT(error, status='fail', code=400):
    return RESULT(status, None, code, error)


# accounts helpers


def get_account_by_username(accounts_collection, username):
    if not is_username_valid(username):
        return None

    username_regex = re.compile(('^%s$' % username), re.IGNORECASE)

    return accounts_collection.find_one({'username': {'$regex': username_regex}})


def get_account_by_token(accounts_collection, token):
    if not is_token_valid(token):
        return None

    return accounts_collection.find_one({'token': token})


def get_account_by_id(accounts_collection, id):
    if not is_id_valid(id):
        return None

    return accounts_collection.find_one({'_id': ObjectId(id)})


# logging


def setup_logger(app, config):
    log_format = '[%(asctime)s] PID %(process)s (%(pathname)s:%(lineno)d) %(levelname)s: %(message)s'

    logging.basicConfig(format=log_format, filename=config.LOG_GLOBAL, level=logging.DEBUG)

    formatter = logging.Formatter(log_format, '%y-%m-%d %H:%M:%S')

    file_handler = logging.FileHandler(config.LOG_SUMMARY)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    stream_handler.setFormatter(formatter)

    app.logger.addHandler(file_handler)
    app.logger.addHandler(stream_handler)

    app.logger.info("Logging has been started.")


def get_basic_request_params(request):
    return {'request_method': request.method,
            'request_url': request.url,
            'remote_addr': request.remote_addr}


def format_log_params(**kwargs):
    log_line = ''
    log_line_template = '%s: %s'
    kw_items = kwargs.items()

    for i, item in enumerate(kw_items):
        if i == 0:
            log_line = '%s' % (log_line_template % (item[0], item[1]))
        else:
            log_line = '%s, %s' % (log_line, log_line_template % (item[0], item[1]))

    return log_line
