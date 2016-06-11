import pymongo
from bson import ObjectId
from flask import Flask
from flask_restful import reqparse, Api, Resource
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, \
    check_password_hash

import config
import utils

# constants

API_PREFIX = '/api/v%s/%s' % (config.VERSION, config.APP_NAME)

# variables

app = Flask(config.APP_NAME)
api = Api(app, API_PREFIX)

db_client = MongoClient(host=config.DB_HOST, port=config.DB_PORT)
accounts_db = db_client.accounts

accounts_collection = accounts_db.accounts


# helper functions


def get_account_by_username(username):
    return accounts_collection.find_one({'username': username})


def get_account_by_token(token):
    return accounts_collection.find_one({'token': token})


def get_account_by_id(id):
    return accounts_collection.find_one({'_id': ObjectId(id)})


def slice_account(account, with_token=True):
    if account is None:
        return None

    out = {'id': str(account['_id']),
           'username': account['username'],
           'role': account['role'],
           'firstName': account['firstName'],
           'lastName': account['lastName']
           }

    if with_token:
        out['token'] = account['token']

    return out


def RESULT(status, result, code):
    out = {'status': status}

    if result is not None:
        out['result'] = result

    return out, code


def RESULT_OK(result=None, code=200):
    return RESULT('ok', result, code)


def RESULT_OK_CREATED(result=None, code=201):
    return RESULT('ok', result, code)


def RESULT_FAIL_ON_CLIENT(status='fail', result=None, code=400):
    return RESULT(status, result, code)


class Account(object):
    def generate_token(self):
        return utils.random_string(32)

    def __init__(self, username, password,
                 tgId=None, role='ghost', studyGroup=None,
                 firstName=None, lastName=None, patronymic=None):
        self.token = self.generate_token()
        self.tgId = tgId
        self.role = role
        self.studyGroup = studyGroup
        self.firstName = firstName
        self.lastName = lastName
        self.patronymic = patronymic
        self.username = username
        self.password = password



class AccountsBasic(Resource):
    '''
    getAccount
    '''
    def get(self, token):
        exclude_fields = ['_id', 'token', 'password']

        matching_acc = get_account_by_token(token)
        matching_acc['id'] = str(matching_acc['_id'])

        if matching_acc is None:
            return RESULT_FAIL_ON_CLIENT()

        return RESULT_OK(result=utils.exclude_fields(matching_acc, exclude_fields))


    '''
    createAccount
    '''
    def post(self, token=None):
        parser = reqparse.RequestParser()

        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)

        args = parser.parse_args()
        args_names = args.keys()

        if 'username' not in args_names or 'password' not in args_names:
            return RESULT_FAIL_ON_CLIENT()

        username = args['username']
        password = args['password']

        if username == None or password == None:
            return RESULT_FAIL_ON_CLIENT()

        # check if username is taken
        acc = get_account_by_username(username)

        if acc is not None:
            # it is, so try choosing another one
            return RESULT_FAIL_ON_CLIENT()

        # create new account

        hashed_password = generate_password_hash(password)

        acc_hash = Account(username, hashed_password).__dict__

        accounts_collection.insert_one(acc_hash)

        return RESULT_OK_CREATED(result=slice_account(acc_hash))


class AccountsAuthorizedActions(Resource):
    def exists(self, token):
        acc = accounts_collection.find_one({'token': token})

        return RESULT_OK(result=acc is not None)

    def updateRole(self, token):
        moderator_account = get_account_by_token(token)

        if moderator_account is None:
            return RESULT_FAIL_ON_CLIENT()

        if moderator_account['role'] != 'moderator':
            return RESULT_FAIL_ON_CLIENT()

        parser = reqparse.RequestParser()

        parser.add_argument('accountId', type=str)
        parser.add_argument('newRole', type=str)

        args = parser.parse_args()
        args_names = args.keys()

        if 'accountId' not in args_names or 'newRole' not in args_names:
            return RESULT_FAIL_ON_CLIENT()

        editable_user_account_id = args['accountId']
        new_role = args['newRole']

        # TODO: advanced permission management

        if editable_user_account_id == None or new_role == None or new_role not in ['student', 'ghost']:
            return RESULT_FAIL_ON_CLIENT()

        editable_action_account = get_account_by_id(editable_user_account_id)
        editable_action_account['role'] = new_role

        accounts_collection.update_one({'_id': ObjectId(editable_action_account['_id'])},
                                       {'$set': {'role': new_role}})

        return RESULT_OK()

    def listAccounts(self, token):
        account = get_account_by_token(token)

        if account == None or account['role'] != 'moderator':
            return RESULT_FAIL_ON_CLIENT()

        found_accounts = list(accounts_collection\
            .find({'role': {'$in': ['student', 'ghost']}})\
            .sort('role', 1))

        found_accounts_slices = []

        for acc in found_accounts:
            found_accounts_slices.append(slice_account(acc, False))

        return RESULT_OK(result=found_accounts_slices)

    def process_request(self, method, token, action):
        handlers = {'get': {'exists': self.exists,
                            'list': self.list},
                    'put': {'updateRole': self.updateRole}}

        # TODO: filter for field names
        if action in dir(self):
            func = handlers[method][action]

            if utils.is_function(func):
                return func(token)
            else:
                return RESULT_FAIL_ON_CLIENT()
        else:
            return RESULT_FAIL_ON_CLIENT()

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
            return RESULT_FAIL_ON_CLIENT()

        username = args['username']
        password = args['password']

        # create new account
        if username == None or password == None:
            return RESULT_FAIL_ON_CLIENT()

        account = get_account_by_username(username)

        if account == None:
            return RESULT_FAIL_ON_CLIENT()

        acc_password = account['password']

        authorized = check_password_hash(acc_password, password)

        if authorized:
            return RESULT_OK(result=slice_account(account))
        else:
            return RESULT_FAIL_ON_CLIENT()

    def post(self, action):
        if action in dir(self):
            func = getattr(self, action)

            if utils.is_function(func):
                return func()
            else:
                return RESULT_FAIL_ON_CLIENT()
        else:
            return RESULT_FAIL_ON_CLIENT()


api.add_resource(AccountsUnauthorizedActions, '/<string:action>')
api.add_resource(AccountsBasic, '/<string:token>', '/')
api.add_resource(AccountsAuthorizedActions, '/<string:token>/<string:action>')


if __name__ == '__main__':
    app.run(config.WEB_HOST, config.WEB_PORT, debug=True)
