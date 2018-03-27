import unittest

import faker

from golem_messages import validators
from golem_messages import exceptions

fake = faker.Faker()


class ValidateVarcharTestCase(unittest.TestCase):
    def setUp(self):
        self.max_length = fake.random_int(min=1)

    def validate(self, value):
        return validators.validate_varchar(
            field_name=fake.word(),
            value=value,
            max_length=self.max_length,
        )

    def test_value_too_long(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate('*'*(self.max_length+1))

    def test_value_valid(self):
        for x in range(self.max_length+1):
            self.validate('*'*x)

    def test_value_invalid_type(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(fake.pyint())


class ValidateIntegerTestCase(unittest.TestCase):
    def setUp(self):
        self.field_name = fake.word()

    def validate(self, value):
        return validators.validate_integer(
            field_name=self.field_name,
            value=value,
        )

    def test_value_valid(self):
        self.validate(fake.pyint())

    def test_value_invalid_type(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(fake.word())
