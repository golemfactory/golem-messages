import unittest

import faker

from golem_messages import validators
from golem_messages import exceptions

fake = faker.Faker()


class ValidateVarcharTestCase(unittest.TestCase):
    def setUp(self):
        self.max_length = fake.random_int(min=0, max=555)

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

    def test_value_str_raises(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(fake.word())

    def test_value_float_raises(self):
        val = fake.pyfloat()
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"Should be an integer \[%s:%r\]" % (self.field_name, val)
        ):
            self.validate(val)

    def test_value_bool_raises(self):
        val = fake.pybool()
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"Should be an integer \[%s:%r\]" % (self.field_name, val)
        ):
            self.validate(val)

    def test_value_list_raises(self):
        val = fake.pylist()
        with self.assertRaises(exceptions.FieldError) as ex:
            self.validate(val)
        self.assertEqual(
            str(ex.exception),
            "Should be an integer [%s:%r]" % (self.field_name, val))


class ValidatePositiveIntegerTestCase(unittest.TestCase):
    def setUp(self):
        self.field_name = fake.word()

    def validate(self, value):
        return validators.validate_positive_integer(
            field_name=self.field_name,
            value=value,
        )

    def test_positive_value_valid(self):
        self.validate(fake.random_int(min=1, max=10e9))

    def test_value_zero_raises(self):
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"Should be a positive integer \[%s:%r\]" % (self.field_name, 0)
        ):
            self.validate(0)

    def test_value_negative_raises(self):
        val = fake.random_int(min=-10e9, max=-1)
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"Should be a positive integer \[%s:%r\]" % (self.field_name, val)
        ):
            self.validate(val)
