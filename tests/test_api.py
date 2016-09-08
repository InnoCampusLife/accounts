import json
import unittest
from functools import reduce

from entry import app, API_PREFIX, accounts_collection
from utils import validators


correct_account_data = {'username': 'a' * validators.MIN_USERNAME_LENGTH,
                        'password': 'l' * validators.MIN_PASSWORD_LENGTH,
                        'firstName': 'f' * validators.MAX_NAME_COMPONENT_LENGTH,
                        'email': 'test@test.ru',
                        'lastName': 'c' * validators.MAX_NAME_COMPONENT_LENGTH}


class getAccountTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()

        self.correct_input_data = {'username': 'p' * validators.MIN_USERNAME_LENGTH,
                                   'password': 'l' * validators.MIN_PASSWORD_LENGTH,
                                   'firstName': 'f' * validators.MAX_NAME_COMPONENT_LENGTH,
                                   'lastName': 'c' * validators.MAX_NAME_COMPONENT_LENGTH,
                                   'email': 'test@test.ru'}
        self.correct_auth_data = {'username': self.correct_input_data['username'],
                                  'password': self.correct_input_data['password']}

    def test_fails_on_wrong_token(self):
        response = self.app.get(API_PREFIX + '/someWrongToken')
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

        response = self.app.get(API_PREFIX + '/' + 'a' * validators.MIN_TOKEN_LENGTH)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj is not None
        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_okay_on_correct_token(self):
        # create new account
        response = self.app.post(API_PREFIX + '/', data=self.correct_input_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        # auth - get token
        response = self.app.post(API_PREFIX + '/auth', data=self.correct_auth_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok'

        # getAccount

        response = self.app.get(API_PREFIX + '/' + json_obj['result']['token'])
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok'

        required_keys = {'firstName', 'lastName', 'patronymic', 'role',
                         'studyGroup', 'tgId', 'username', 'id', 'email'}
        result_keys = set(json_obj['result'].keys())

        assert result_keys == required_keys
        assert 200 <= response.status_code < 300


class createAccountTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.accounts_collection = accounts_collection
        self.insufficient_data_acc = {'username': 'test'}
        self.illegal_username = {'username': 't' * (validators.MIN_USERNAME_LENGTH - 1),
                                 'password': '1' * validators.MIN_PASSWORD_LENGTH,
                                 'firstName': 'A' * validators.MIN_NAME_COMPONENT_LENGTH,
                                 'email': 'test@test.ru',
                                 'lastName': 'B' * validators.MIN_NAME_COMPONENT_LENGTH}
        self.illegal_password = {'username': 't' * validators.MIN_USERNAME_LENGTH,
                                 'password': '1' * (validators.MIN_PASSWORD_LENGTH - 1),
                                 'firstName': 'A' * validators.MIN_NAME_COMPONENT_LENGTH,
                                 'email': 'test@test.ru',
                                 'lastName': 'B' * validators.MIN_NAME_COMPONENT_LENGTH}
        self.illegal_input_data_acc = {'username': 't' * validators.MIN_USERNAME_LENGTH,
                                       'password': '1' * validators.MIN_PASSWORD_LENGTH,
                                       'firstName': 'A' * (validators.MIN_NAME_COMPONENT_LENGTH - 1),
                                       'email': 'test@test.ru',
                                       'lastName': 'B' * (validators.MIN_NAME_COMPONENT_LENGTH - 1)}
        self.illegal_optional_input_data_acc = {'username': 't' * validators.MIN_USERNAME_LENGTH,
                                                'password': '1' * validators.MIN_PASSWORD_LENGTH,
                                                'firstName': 'A' * validators.MIN_NAME_COMPONENT_LENGTH,
                                                'email': 'test@test.ru',
                                                'lastName': 'B' * validators.MIN_NAME_COMPONENT_LENGTH,
                                                'studyGroup': 'Z' * (validators.MIN_STUDY_GROUP_LENGTH - 1)}
        self.correct_required_input_data = correct_account_data
        self.correct_optional_input_data = {'username': 'a' * validators.MIN_USERNAME_LENGTH,
                                            'password': 'l' * validators.MIN_PASSWORD_LENGTH,
                                            'firstName': 'f' * validators.MAX_NAME_COMPONENT_LENGTH,
                                            'email': 'test@test.ru',
                                            'lastName': 'c' * validators.MAX_NAME_COMPONENT_LENGTH,
                                            'studyGroup': 'Z' * validators.MIN_STUDY_GROUP_LENGTH}
        # be sure not to have any test accounts before we run tests
        self.accounts_collection.delete_many(self.insufficient_data_acc)
        self.accounts_collection.delete_many({'username': self.correct_required_input_data['username']})

        self.response_required_fields = {'id', 'token', 'username', 'firstName', 'lastName', 'role'}

    def test_fails_on_insufficient_input_data(self):
        response = self.app.post(API_PREFIX + '/', data=self.insufficient_data_acc)
        json_obj = json.loads(response.data.decode('utf-8'))

        all_fields = ['username', 'password', 'firstName', 'password', 'email']
        required_fields = list(set(all_fields) - set(self.insufficient_data_acc.keys()))

        error = json_obj['error']

        assert json_obj['status'] == 'fail'
        assert reduce(lambda a, b: a and b, [field_name in error for field_name in required_fields])
        assert 400 <= response.status_code < 500

    # now, check concrete fields

    def test_fails_on_illegal_username(self):
        response = self.app.post(API_PREFIX + '/', data=self.illegal_username)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert (lambda err_text: 'username' in err_text)(json_obj['error'])
        assert 400 <= response.status_code < 500

    def test_fails_on_illegal_password(self):
        response = self.app.post(API_PREFIX + '/', data=self.illegal_password)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert (lambda err_text: 'password' in err_text)(json_obj['error'])
        assert 400 <= response.status_code < 500

    def test_fails_on_illegal_required_input(self):
        response = self.app.post(API_PREFIX + '/', data=self.illegal_input_data_acc)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_fails_on_illegal_optional_input(self):
        response = self.app.post(API_PREFIX + '/', data=self.illegal_optional_input_data_acc)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_success_on_correct_required_input(self):
        response = self.app.post(API_PREFIX + '/', data=self.correct_required_input_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok'

        actual_response_fields = set(json_obj['result'].keys())

        assert json_obj['status'] == 'ok' and (self.response_required_fields == actual_response_fields)
        assert 200 <= response.status_code < 300

    def test_success_on_correct_optional_input(self):
        response = self.app.post(API_PREFIX + '/', data=self.correct_optional_input_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        actual_response_fields = set(json_obj['result'].keys())

        assert json_obj['status'] == 'ok' and (self.response_required_fields == actual_response_fields)
        assert 200 <= response.status_code < 300


class existsTestCase(unittest.TestCase):
    # TODO: stopped at implementation of exists method
    def setUp(self):
        self.app = app.test_client()
        self.accounts_collection = accounts_collection
        self.accounts_collection.delete_many({'username': correct_account_data['username']})

    def test_fails_on_illegal_token(self):
        response = self.app.get(API_PREFIX + '/' + ('t' * validators.MIN_TOKEN_LENGTH) + '/exists',
                                data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_fails_on_no_arguments(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        response = self.app.get(API_PREFIX + '/' + json_obj['result']['token'] + '/exists')
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_fails_on_too_many_arguments(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        response = self.app.get(API_PREFIX + '/' + json_obj['result']['token'] + '/exists',
                                data={'id': 'x' * validators.MIN_ID_LENGTH,
                                      'username': 'u' * validators.MIN_USERNAME_LENGTH})
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_fails_on_illegal_arguments(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        token = json_obj['result']['token']

        response = self.app.get(API_PREFIX + '/' + token + '/exists',
                                data={'id': 'x' * (validators.MIN_ID_LENGTH - 1)})
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

        response = self.app.get(API_PREFIX + '/' + token + '/exists',
                                data={'username': 'u' * (validators.MIN_USERNAME_LENGTH - 1)})
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_success_on_correct_id(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        token = json_obj['result']['token']
        user_id = json_obj['result']['id']

        response = self.app.get(API_PREFIX + '/' + token + '/exists', query_string={'id': user_id})
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok'
        assert 200 <= response.status_code < 300

    def test_success_on_correct_username(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        token = json_obj['result']['token']
        username = json_obj['result']['username']

        response = self.app.get(API_PREFIX + '/' + token + '/exists', query_string={'username': username})
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok'
        assert 200 <= response.status_code < 300


class getBioTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.accounts_collection = accounts_collection
        self.accounts_collection.delete_many({'username': correct_account_data['username']})
        self.expected_fields = {'firstName', 'lastName', 'studyGroup', 'role', 'username', 'id'}

    def set_role(self, new_role):
        self.accounts_collection.update({'username': correct_account_data['username']},
                                        {'$set': {'role': new_role}})

    def test_fails_on_no_arguments(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        response = self.app.get(API_PREFIX + '/' + json_obj['result']['token'] + '/getBio')
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_fails_on_too_many_arguments(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        response = self.app.get(API_PREFIX + '/' + json_obj['result']['token'] + '/getBio',
                                data={'id': 'x' * validators.MIN_ID_LENGTH,
                                      'username': 'u' * validators.MIN_USERNAME_LENGTH})
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_fails_on_illegal_arguments(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        token = json_obj['result']['token']

        response = self.app.get(API_PREFIX + '/' + token + '/getBio',
                                data={'id': 'x' * (validators.MIN_ID_LENGTH - 1)})
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

        response = self.app.get(API_PREFIX + '/' + token + '/getBio',
                                data={'username': 'u' * (validators.MIN_USERNAME_LENGTH - 1)})
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'fail'
        assert 400 <= response.status_code < 500

    def test_success_on_correct_id(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        self.set_role('student')

        token = json_obj['result']['token']
        user_id = json_obj['result']['id']

        response = self.app.get(API_PREFIX + '/' + token + '/getBio', query_string={'id': user_id})
        json_obj = json.loads(response.data.decode('utf-8'))

        result_fields = set(json_obj['result'].keys())

        assert json_obj['status'] == 'ok'
        assert result_fields == self.expected_fields
        assert 200 <= response.status_code < 300

    def test_success_on_correct_username(self):
        # first of all, create an account and get a valid token
        response = self.app.post(API_PREFIX + '/', data=correct_account_data)
        json_obj = json.loads(response.data.decode('utf-8'))

        assert json_obj['status'] == 'ok' or \
               (json_obj['status'] == 'fail' and json_obj['error'] == 'Username is already taken')

        self.set_role('student')

        token = json_obj['result']['token']
        username = json_obj['result']['username']

        response = self.app.get(API_PREFIX + '/' + token + '/getBio', query_string={'username': username})
        json_obj = json.loads(response.data.decode('utf-8'))

        result_fields = set(json_obj['result'].keys())

        assert json_obj['status'] == 'ok'
        assert result_fields == self.expected_fields
        assert 200 <= response.status_code < 300

