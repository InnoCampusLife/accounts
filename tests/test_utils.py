import unittest

import utils.common


class FilterFieldsTestCase(unittest.TestCase):
    def setUp(self):
        self.data = {'one': 1, 'two': 2}

    def test_no_args(self):
        self.assertEqual(utils.common.filter_fields(self.data, None), {})

    def test_no_data(self):
        self.assertEqual(utils.common.filter_fields(None, None), None)

    def test_exclude_fields(self):
        self.assertEqual(utils.common.filter_fields(self.data, ['one']), {'two': 2})

    def test_keep_fields(self):
        self.assertEqual(utils.common.filter_fields(self.data, None, ['one']), {'one': 1})

    def test_exclude_non_existing_fields(self):
        self.assertEqual(utils.common.filter_fields(self.data, ['three']), self.data)

    def test_keep_non_existing_fields(self):
        self.assertEqual(utils.common.filter_fields(self.data, None, ['three']), {})

    def test_exclude_id(self):
        self.assertEqual(utils.common.filter_fields({'_id': 0}, ['id']), {})

    def test_keep_id(self):
        self.assertEqual(utils.common.filter_fields({'_id': '0'}, None, ['id']), {'id': '0'})




if __name__ == '__main__':
    unittest.main()