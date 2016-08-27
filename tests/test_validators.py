import string
import unittest

from utils import validators


class ValidateString(unittest.TestCase):
    def setUp(self):
        self.update_preferences(None, None, None, None, None, True)

    def update_preferences(self, min_length, max_length, validator_func,
                           illegal_characters=None, legal_characters_sample=None,
                           skip_tests=False):
        self.min_length = min_length
        self.max_length = max_length
        self.validator_func = validator_func
        self.illegal_characters = [] if illegal_characters is None else illegal_characters
        self.legal_characters_sample = '' if legal_characters_sample is None else legal_characters_sample
        self.skip_tests = skip_tests

    # Illegal cases

    def test_empty(self, skip=False):
        if self.skip_tests or skip:
            return

        self.assertEqual(self.validator_func(''), False)

    def test_too_short(self, skip=False):
        if self.skip_tests or skip:
            return

        self.assertEqual(self.validator_func(self.legal_characters_sample[0] * (self.min_length - 1)), False)

    def test_too_long(self, skip=False):
        if self.skip_tests or skip:
            return

        self.assertEqual(self.validator_func(self.legal_characters_sample[0] * (self.max_length + 1)), False)

    def test_illegal_characters(self, skip=False):
        if self.skip_tests or skip:
            return

        for illegal_character in self.illegal_characters:
            str_sample = illegal_character * (self.min_length + 1)
            result = self.validator_func(str_sample)

            self.assertEqual(result, False)

    # Legal cases

    def test_not_too_short(self, skip=False):
        if self.skip_tests or skip:
            return

        self.assertEqual(self.validator_func(self.legal_characters_sample[0] * self.min_length), True)

    def test_not_too_long(self, skip=False):
        if self.skip_tests or skip:
            return

        print(self.legal_characters_sample[0] * self.max_length)

        self.assertEqual(self.validator_func(self.legal_characters_sample[0] * self.max_length), True)

    def test_legal_characters(self, skip=False):
        if self.skip_tests or skip:
            return

        str_sample = (self.legal_characters_sample * self.min_length)\
            [:min(max(self.min_length, int((self.max_length + self.min_length) / 2 - 1)), self.max_length)]
        result = self.validator_func(str_sample)

        self.assertEqual(result, True)


class ValidateUsernameTestCase(ValidateString):
    def setUp(self):
        illegal_characters = [*string.punctuation, *string.whitespace]
        illegal_characters.remove('_')  # underscore is still legal

        self.update_preferences(validators.MIN_USERNAME_LENGTH, validators.MAX_USERNAME_LENGTH,
                                validators.is_username_valid, illegal_characters,
                                legal_characters_sample='a_')


class ValidatePasswordTestCase(ValidateString):
    def setUp(self):
        self.update_preferences(validators.MIN_PASSWORD_LENGTH, validators.MAX_PASSWORD_LENGTH,
                                validators.is_password_valid, legal_characters_sample='a_')


class ValidateNameComponentTestCase(ValidateString):
    def setUp(self):
        self.update_preferences(validators.MIN_NAME_COMPONENT_LENGTH, validators.MAX_NAME_COMPONENT_LENGTH,
                                validators.is_name_component_valid, legal_characters_sample='0- Š',
                                illegal_characters=['\t', '⏳'])


class ValidateStudyGroupTestCase(ValidateString):
    def setUp(self):
        self.update_preferences(validators.MIN_STUDY_GROUP_LENGTH, validators.MAX_STUDY_GROUP_LENGTH,
                                validators.is_study_group_valid, legal_characters_sample='0-M',
                                illegal_characters=['\t', '⏳', '%'])


class ValidateEmailTestCase(unittest.TestCase):
    def test_cases(self):
        mixins = [{'legal': True, 'sample': 'd'},
                  {'legal': False, 'sample': '#'},
                  {'legal': False, 'sample': '⏳'},
                  {'legal': False, 'sample': 'Š'},
                  {'legal': True, 'sample': '3'},
                  {'legal': False, 'sample': '@'}]

        email_samples = ['qwe%srty@qwerty.com', 'qwerty@qwe%srty.com', 'qwerty@qwerty.c%sm']

        for email_sample in email_samples:
            for mixin in mixins:
                email = email_sample % mixin['sample']
                self.assertEqual(validators.is_email_valid(email), mixin['legal'])


class ValidateTokenTestCase(ValidateString):
    def setUp(self):
        self.update_preferences(validators.MIN_TOKEN_LENGTH, validators.MAX_TOKEN_LENGTH,
                                validators.is_token_valid, legal_characters_sample='0vM',
                                illegal_characters=['\t', '⏳', '%'])


class ValidateIdTestCase(ValidateString):
    def setUp(self):
        self.update_preferences(validators.MIN_ID_LENGTH, validators.MAX_ID_LENGTH,
                                validators.is_id_valid, legal_characters_sample='0vM',
                                illegal_characters=['\t', '⏳', '%'])

if __name__ == '__main__':
    unittest.main()
