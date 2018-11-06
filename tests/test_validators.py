import enum
import unittest

import faker

from golem_messages import validators
from golem_messages import exceptions
from golem_messages.datastructures import StringEnum
from golem_messages.factories.tasks import BlenderScriptPackageFactory
from golem_messages.factories.tasks import ComputeTaskDefFactory
from golem_messages.message import tasks

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


class ValidateBooleanTestCase(unittest.TestCase):
    def setUp(self):
        self.field_name = fake.word()

    def validate(self, value):
        return validators.validate_boolean(
            field_name=self.field_name,
            value=value
        )

    def test_that_boolean_value_will_not_raise_exception(self):
        for value in [False, True]:
            self.validate(value)

    def test_that_not_boolean_value_will_raise_exception(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate('True')

        with self.assertRaises(exceptions.FieldError):
            self.validate(123)


class ValidateListTestCase(unittest.TestCase):
    def setUp(self):
        self.field_name = fake.word()
        self.correct_value = fake.pylist(
            nb_elements=3,
            variable_nb_elements=False,
        )
        self.incorrect_value = fake.pylist(
            nb_elements=4,
            variable_nb_elements=False,
        )
        self.empty_list = []
        self.min_length = 1
        self.max_length = 3

    def validate(self, value):
        return validators.validate_list(
            field_name=self.field_name,
            min_length=self.min_length,
            max_length=self.max_length,
            value=value,
        )

    def test_that_correct_value_will_not_raise_exception(self):
        self.validate(self.correct_value)

    def test_that_incorrect_value_will_raise_exception(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(self.incorrect_value)

        with self.assertRaises(exceptions.FieldError):
            self.validate(self.empty_list)


class ValidateListOfIntegersTestCase(unittest.TestCase):
    def setUp(self):
        self.field_name = fake.word()
        self.correct_value = [1, 2, 3]
        self.incorrect_value = [1.2, 0., 1.0]
        self.min_length = 1
        self.max_length = 3

    def validate(self, value):
        return validators.validate_list_of_positive_integers(
            field_name=self.field_name,
            value=value,
            min_length=self.min_length,
            max_length=self.max_length,
        )

    def test_that_correct_value_will_not_raise_exception(self):
        self.validate(self.correct_value)

    def test_that_incorrect_value_will_raise_exception(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(self.incorrect_value)


class ValidateListOfFloatsTestCase(unittest.TestCase):
    def setUp(self):
        self.field_name = fake.word()
        self.correct_value = [1.2, 3.4, 5.6]
        self.incorrect_value = [1, 2, 3]
        self.min_length = 1
        self.max_length = 3

    def validate(self, value):
        return validators.validate_list_of_non_negative_floats(
            field_name=self.field_name,
            value=value,
            min_length=self.min_length,
            max_length=self.max_length,
        )

    def test_that_correct_value_will_not_raise_exception(self):
        self.validate(self.correct_value)

    def test_that_incorrect_value_will_raise_exception(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(self.incorrect_value)


class ValidateEnumTestCase(unittest.TestCase):
    def setUp(self):
        self.correct_value = 'Test'
        self.incorrect_value = 'Wrong_test'
        self.field_name = fake.word()

    class EnumTest(StringEnum):
        Test = enum.auto()

    def validate(self, value, enum_class):
        return validators.validate_enum(
            field_name=self.field_name,
            value=value,
            enum_class=enum_class,
        )

    def test_that_correct_enum_value_will_not_raise_exception(self):
        self.validate(
            value=self.correct_value,
            enum_class=self.EnumTest
        )

    def test_that_incorrect_enum_value_will_raise_exception(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(
                value=self.incorrect_value,
                enum_class=self.EnumTest,
            )


class ValidateTaskTypeWithMetaParametersTestCase(unittest.TestCase):
    def setUp(self):
        self.field_name = fake.word()
        self.valid_pair = {
            tasks.TaskType.Blender.name: tasks.BlenderScriptPackage,
        }
        self.blender_script_package = BlenderScriptPackageFactory()
        self.blender_script_package_correct_value = {
            'task_type': tasks.TaskType.Blender.name,
            'meta_parameters': self.blender_script_package
        }
        self.incorrect_pair = {
            'task_type': tasks.TaskType.Blender.name,
            'meta_parameters': {}
        }

    def validate(self, value):
        return validators.validate_task_type_with_meta_parameters(
            field_name=self.field_name,
            task_type=value['task_type'],
            meta_parameters=value['meta_parameters'],
            task_type_meta_parameters=self.valid_pair,
        )

    def test_that_correct_pairs_values_will_not_raise_excpetion(self):
        self.validate(self.blender_script_package_correct_value)

    def test_that_incorrect_pair_values_will_raise_exception(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(self.incorrect_pair)


class ValidateCorrectMetaParametersClass(unittest.TestCase):
    def setUp(self):
        self.meta_parameters_classes = tasks.ComputeTaskDef.TASK_TYPE_META_PARAMETERS.values()  # noqa pylint: disable=line-too-long
        self.compute_task_def = ComputeTaskDefFactory()
        self.correct_values = self.compute_task_def
        self.incorrect_values = [
            '',
            self.compute_task_def,
            None,
        ]

    def validate(self, value):
        return validators.validate_correct_meta_parameters_class(
            self.meta_parameters_classes,
            value=value
        )

    def test_that_validator_will_not_raise_exception_when_meta_parameters_are_correct(self):  # noqa pylint: disable=line-too-long
        self.validate(self.correct_values['extra_data']['meta_parameters'])

    def test_that_validator_will_raise_exception_when_meta_parameters_is_empty_string(self):  # noqa pylint: disable=line-too-long
        with self.assertRaises(exceptions.FieldError):
            self.validate(self.incorrect_values[0])

    def test_that_validator_will_raise_exception_when_value_is_not_an_instance_of_meta_parameters_classes(self):  # noqa pylint: disable=line-too-long
        with self.assertRaises(exceptions.FieldError):
            self.validate(self.incorrect_values[1])

    def test_that_validator_will_raise_exception_when_value_is_none(self):
        with self.assertRaises(exceptions.FieldError):
            self.validate(self.incorrect_values[2])
