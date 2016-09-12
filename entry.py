import json
import logging
import os
import re

from bson import ObjectId
from flask import Flask
from flask_restful import reqparse, Api, Resource, request
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, \
    check_password_hash

import config
import utils
import utils.common
from utils.validators import is_password_valid, is_name_component_valid, is_study_group_valid, is_email_valid, \
    is_token_valid, is_id_valid, is_preferences_valid
from utils.validators import is_username_valid

# constants

API_PREFIX = '/api/v%s/%s' % (config.VERSION, config.APP_NAME)

# variables

app = Flask(config.APP_NAME)
api = Api(app=app, prefix=API_PREFIX)

db_client = MongoClient(host=config.DB_HOST, port=config.DB_PORT)
accounts_db = db_client.accounts

accounts_collection = accounts_db.accounts


# helper functions


def get_account_by_username(username):
    if not is_username_valid(username):
        return None

    username_regex = re.compile(('^%s$' % username), re.IGNORECASE)

    return accounts_collection.find_one({'username': {'$regex': username_regex}})


def get_account_by_token(token):
    if not is_token_valid(token):
        return None

    return accounts_collection.find_one({'token': token})


def get_account_by_id(id):
    if not is_id_valid(id):
        return None

    return accounts_collection.find_one({'_id': ObjectId(id)})


def RESULT(status, result, code, error):
    out = {'status': status}

    if result is not None:
        out['result'] = result

    if error is not None:
        out['error'] = error

    return out, code


def RESULT_OK(result=None, code=200):
    return RESULT('ok', result, code, None)


def RESULT_OK_CREATED(result=None, code=201):
    return RESULT('ok', result, code, None)


def RESULT_FAIL_ON_CLIENT(error, status='fail', code=400):
    return RESULT(status, None, code, error)


def setup_logger():
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


# routing


class Account(object):
    def generate_token(self):
        return utils.common.random_string(32)

    def __init__(self, username, password,
                 firstName, lastName, studyGroup, email,
                 tgId=None, role='ghost', patronymic=None):
        self.username = username
        self.password = password
        self.firstName = firstName
        self.lastName = lastName
        self.studyGroup = studyGroup
        self.email = email
        self.tgId = tgId
        self.role = role
        self.patronymic = patronymic
        self.token = self.generate_token()


class AccountsBasic(Resource):
    '''
    getAccount
    '''

    def get(self, token):
        app.logger.info(format_log_params(**get_basic_request_params(request),
                                          method='getAccount',
                                          token=token))
        exclude_fields = ['token', 'password', 'preferences']

        matching_acc = get_account_by_token(token)

        if matching_acc is None:
            return RESULT_FAIL_ON_CLIENT('Unknown token')

        return RESULT_OK(result=utils.common.filter_dict_fields(matching_acc, exclude_fields))

    def post(self, token=None):
        """
        createAccount
        """
        app.logger.info(format_log_params(**get_basic_request_params(request),
                                          method='createAccount',
                                          token=token))
        parser = reqparse.RequestParser()

        required_arg_names = ['username', 'password', 'firstName',
                              'lastName', 'email']
        optional_arg_names = ['studyGroup']

        for required_arg_name in required_arg_names:
            parser.add_argument(required_arg_name, type=str)

        for optional_arg_name in optional_arg_names:
            parser.add_argument(optional_arg_name, type=str)

        incoming_args = parser.parse_args()
        incoming_args_names = incoming_args.keys()
        missing_required_arg_names = []

        for required_arg_name in required_arg_names:
            if required_arg_name not in incoming_args_names or \
                            incoming_args.get(required_arg_name) is None:
                missing_required_arg_names.append(required_arg_name)

        if len(missing_required_arg_names) > 0:
            missing_args_str = ', '.join(missing_required_arg_names)
            return RESULT_FAIL_ON_CLIENT('The following required arguments are missing: %s' % missing_args_str)

        username = incoming_args['username']
        password = incoming_args['password']

        if (not is_username_valid(username)) or (not is_password_valid(password)):
            return RESULT_FAIL_ON_CLIENT('Incorrect username or password formation: illegal length or content')

        # check if username is taken
        acc = get_account_by_username(username)

        if acc is not None:
            # it is, so try choosing another one
            return RESULT_FAIL_ON_CLIENT('Username is already taken')

        # create new account

        # first of all, let's check the rest of the arguments
        # required:

        first_name = incoming_args['firstName']
        last_name = incoming_args['lastName']

        # optional:

        study_group = incoming_args['studyGroup']
        email = incoming_args['email']

        all_fields_valid = is_name_component_valid(first_name) \
                           and is_name_component_valid(last_name) \
                           and (True if study_group is None else is_study_group_valid(study_group)) \
                           and (True if email is None else is_email_valid(email))

        if not all_fields_valid:
            return RESULT_FAIL_ON_CLIENT('Some of the fields provided are not valid')

        hashed_password = generate_password_hash(password)

        acc_hash = Account(username, hashed_password, firstName=first_name,
                           lastName=last_name, studyGroup=study_group,
                           email=email).__dict__

        accounts_collection.insert_one(acc_hash)

        return RESULT_OK_CREATED(
            result=utils.common.filter_dict_fields(
                acc_hash, None,
                ['id', 'username', 'role',
                 'firstName', 'lastName', 'token']))


class AccountsAuthorizedActions(Resource):
    def exists(self, token):
        app.logger.info(format_log_params(**get_basic_request_params(request),
                                          method='exists',
                                          token=token))
        if not is_token_valid(token):
            return RESULT_FAIL_ON_CLIENT('Unknown token')

        searcher_acc = accounts_collection.find_one({'token': token})

        if searcher_acc is None:
            return RESULT_FAIL_ON_CLIENT('Unknown token')

        parser = reqparse.RequestParser()

        parser.add_argument('id', type=str)
        parser.add_argument('username', type=str)

        args = parser.parse_args()

        user_id = args.get('id')
        username = args.get('username')

        if (lambda empty_fields_count: empty_fields_count != 1)([user_id, username].count(None)):
            return RESULT_FAIL_ON_CLIENT('Wrong arguments set: only one of the fields - username or id  - must be set')

        searched_acc = None

        if user_id is not None:
            if not is_id_valid(user_id):
                return RESULT_FAIL_ON_CLIENT('Invalid params')

            searched_acc = get_account_by_id(user_id)
        elif username is not None:
            if not is_username_valid(username):
                return RESULT_FAIL_ON_CLIENT('Invalid params')

            searched_acc = get_account_by_username(username)

        return RESULT_OK(result=searched_acc is not None)

    def updateRole(self, token):
        moderator_account = get_account_by_token(token)

        if moderator_account is None:
            return RESULT_FAIL_ON_CLIENT('Unknown token')

        if moderator_account['role'] != 'moderator':
            return RESULT_FAIL_ON_CLIENT('Unexpected account role. Needed: moderator')

        parser = reqparse.RequestParser()

        parser.add_argument('accountId', type=str)
        parser.add_argument('newRole', type=str)

        args = parser.parse_args()
        args_names = args.keys()

        if 'accountId' not in args_names or 'newRole' not in args_names:
            return RESULT_FAIL_ON_CLIENT('No accountID specified')

        editable_user_account_id = args['accountId']
        new_role = args['newRole']

        # TODO: advanced permission management

        if (editable_user_account_id is None) or (new_role is None) or new_role not in ['student', 'ghost']:
            return RESULT_FAIL_ON_CLIENT('accountID provided is not valid(probably, roles do not match)')

        editable_action_account = get_account_by_id(editable_user_account_id)
        editable_action_account['role'] = new_role

        accounts_collection.update_one({'_id': ObjectId(editable_action_account['_id'])},
                                       {'$set': {'role': new_role}})

        return RESULT_OK()

    def listAccounts(self, token):
        account = get_account_by_token(token)

        if account is None or account['role'] != 'moderator':
            return RESULT_FAIL_ON_CLIENT('Unknown token')

        found_accounts = list(accounts_collection \
                              .find({'role': {'$in': ['student', 'ghost']}}) \
                              .sort('role', 1))

        found_accounts_slices = []

        for acc in found_accounts:
            found_accounts_slices \
                .append(utils.common.filter_dict_fields(acc,
                                                        None,
                                                        ['id', 'username', 'role', 'firstName', 'lastName']))

        return RESULT_OK(result=found_accounts_slices)

    def getBio(self, token):
        account = get_account_by_token(token)

        if account is None or account['role'] not in ['student', 'moderator']:
            return RESULT_FAIL_ON_CLIENT('Unknown token')

        parser = reqparse.RequestParser()

        parser.add_argument('id', type=str)
        parser.add_argument('username', type=str)

        args = parser.parse_args()

        user_id = args.get('id')
        username = args.get('username')

        if (lambda empty_fields_count: empty_fields_count != 1)([user_id, username].count(None)):
            return RESULT_FAIL_ON_CLIENT('Wrong arguments set: only one of the fields - username or id  - must be set')

        searched_acc = None

        if user_id is not None:
            if not is_id_valid(user_id):
                return RESULT_FAIL_ON_CLIENT('Invalid params')

            searched_acc = get_account_by_id(user_id)
        elif username is not None:
            if not is_username_valid(username):
                return RESULT_FAIL_ON_CLIENT('Invalid params')

            searched_acc = get_account_by_username(username)

        if searched_acc is None:
            return RESULT_FAIL_ON_CLIENT('User not found')

        return RESULT_OK(result=utils.common.filter_dict_fields(searched_acc, None,
                                                                keep_fields=['username', 'id', 'role',
                                                                             'firstName', 'lastName',
                                                                             'studyGroup']))

    def getPreferences(self, token):
        # TODO: +tests
        account = get_account_by_token(token)

        if account is None:
            return RESULT_FAIL_ON_CLIENT('Unknown token')

        preferences = account.get('preferences')

        if preferences is None:
            preferences = {}

        return RESULT_OK(result=preferences)

    def updatePreferences(self, token):
        # TODO: +tests
        account = get_account_by_token(token)

        if account is None:
            return RESULT_FAIL_ON_CLIENT('Unknown token')

        parser = reqparse.RequestParser()

        parser.add_argument('preferences', type=str)

        args = parser.parse_args()
        preferences_str = args.get('preferences')

        if preferences_str is None:
            return RESULT_FAIL_ON_CLIENT('No preferences provided')

        if not is_preferences_valid(preferences_str):
            return RESULT_FAIL_ON_CLIENT('preferences are not valid')

        try:
            preferences = json.loads(preferences_str)
        except:
            return RESULT_FAIL_ON_CLIENT('preferences are not valid')

        accounts_collection.update_one({'_id': ObjectId(account['_id'])},
                                       {'$set': {'preferences': preferences}})

        return RESULT_OK()

    def process_request(self, method, token, action):
        app.logger.info(format_log_params(**get_basic_request_params(request),
                                          method=action,
                                          token=token))
        handlers = {'get': {'exists': self.exists,
                            'listAccounts': self.listAccounts,
                            'getBio': self.getBio,
                            'getPreferences': self.getPreferences},
                    'put': {'updateRole': self.updateRole,
                            'updatePreferences': self.updatePreferences}}

        if action in dir(self):
            if method not in handlers.keys() or action not in handlers[method]:
                return RESULT_FAIL_ON_CLIENT('No action handler provided for action: %s' % action)

            func = handlers[method][action]

            if utils.common.is_function(func):
                return func(token)
            else:
                return RESULT_FAIL_ON_CLIENT('No action handler provided for action: %s' % action)
        else:
            return RESULT_FAIL_ON_CLIENT('No action handler provided for action: %s' % action)

    def get(self, token, action):
        return self.process_request('get', token, action)

    def post(self, token, action):
        return self.process_request('post', token, action)

    def put(self, token, action):
        return self.process_request('put', token, action)


class AccountsUnauthorizedActions(Resource):
    def auth(self):
        parser = reqparse.RequestParser()

        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)

        args = parser.parse_args()
        args_names = args.keys()

        if 'username' not in args_names or 'password' not in args_names:
            return RESULT_FAIL_ON_CLIENT('Missing username or password parameters')

        username = args['username']
        password = args['password']

        # create new account
        if username is None or password is None:
            return RESULT_FAIL_ON_CLIENT('Missing username or password parameters')

        account = get_account_by_username(username)

        if account is None:
            return RESULT_FAIL_ON_CLIENT('Unknown username or password')

        acc_password = account['password']

        authorized = check_password_hash(acc_password, password)

        if authorized:
            return RESULT_OK(
                result=utils.common.filter_dict_fields(account,
                                                       None,
                                                       ['id', 'username', 'role',
                                                        'firstName', 'lastName', 'token']))
        else:
            return RESULT_FAIL_ON_CLIENT('Unknown username or password')

    def post(self, action):
        app.logger.info(format_log_params(**get_basic_request_params(request),
                                          method=action))
        if action in dir(self):
            func = getattr(self, action)

            if utils.common.is_function(func):
                return func()
            else:
                return RESULT_FAIL_ON_CLIENT('No action handler provided for action: %s' % action)
        else:
            return RESULT_FAIL_ON_CLIENT('No action handler provided for action: %s' % action)


api.add_resource(AccountsUnauthorizedActions, '/<string:action>')
api.add_resource(AccountsBasic, '/<string:token>', '/')
api.add_resource(AccountsAuthorizedActions, '/<string:token>/<string:action>')

if __name__ == '__main__':
    # setup_logger()

    run_mode = os.environ.get('RUN_MODE')

    app.run(config.WEB_HOST, config.WEB_PORT, debug=(run_mode == 'dev'))

