import string
import unittest

from utils import validators


class ValidateUsernameTestCase(unittest.TestCase):
    # Illegal cases

    def test_empty_username(self):
        self.assertEqual(validators.is_username_valid(''), False)

    def test_too_short(self):
        self.assertEqual(validators.is_username_valid('a' * (validators.MIN_USERNAME_LENGTH - 1)), False)

    def test_too_long(self):
        self.assertEqual(validators.is_username_valid('a' * (validators.MAX_USERNAME_LENGTH + 1)), False)

    def test_illegal_characters(self):
        illegal_characters = [*string.punctuation, *string.whitespace]
        illegal_characters.remove('_')  # underscore is still legal

        for illegal_character in illegal_characters:
            self.assertEqual(validators.is_username_valid(illegal_character * (validators.MIN_USERNAME_LENGTH + 1)),
                             False)

    # Legal cases

    def test_not_too_short(self):
        self.assertEqual(validators.is_username_valid('a' * validators.MIN_USERNAME_LENGTH), True)

    def test_not_too_long(self):
        self.assertEqual(validators.is_username_valid('a' * validators.MAX_USERNAME_LENGTH), True)

    def test_legal_characters(self):
        frequency = 3

        self.assertEqual(
            validators.is_username_valid(('_a' * (validators.MIN_USERNAME_LENGTH * frequency + 1))[::frequency]), True)


class ValidatePasswordTestCase(unittest.TestCase):
    # Illegal cases

    def test_empty_password(self):
        self.assertEqual(validators.is_password_valid(''), False)

    def test_too_short_password(self):
        self.assertEqual(validators.is_password_valid('a' * (validators.MIN_PASSWORD_LENGTH - 1)), False)

    def test_too_long_password(self):
        self.assertEqual(validators.is_password_valid('a' * (validators.MAX_PASSWORD_LENGTH + 1)), False)

    # Legal cases

    def test_not_too_short_password(self):
        self.assertEqual(validators.is_password_valid('a' * validators.MIN_PASSWORD_LENGTH), True)

    def test_not_too_long_password(self):
        self.assertEqual(validators.is_password_valid('a' * validators.MAX_PASSWORD_LENGTH), True)

    def test_legal_password(self):
        frequency = 3

        self.assertEqual(
            validators.is_password_valid(('_a' * (validators.MIN_PASSWORD_LENGTH * frequency + 1))[::frequency]), True)


if __name__ == '__main__':
    unittest.main()
