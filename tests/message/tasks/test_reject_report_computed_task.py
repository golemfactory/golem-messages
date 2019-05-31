import unittest

from golem_messages import exceptions
from golem_messages import factories
from golem_messages import message

from tests.message import mixins, helpers


class RejectReportComputedTaskTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = message.tasks.RejectReportComputedTask
    FACTORY = factories.tasks.RejectReportComputedTaskFactory.\
        with_task_to_compute
    TASK_ID_PROVIDER = 'attached_task_to_compute'


class RejectRctCctTestCase(mixins.TaskIdMixin, unittest.TestCase):
    MSG_CLASS = message.tasks.RejectReportComputedTask
    FACTORY = factories.tasks.RejectReportComputedTaskFactory.\
        with_cannot_compute_task
    TASK_ID_PROVIDER = 'cannot_compute_task'


class RejectRctTfTestCase(mixins.TaskIdMixin, unittest.TestCase):
    MSG_CLASS = message.tasks.RejectReportComputedTask
    FACTORY = factories.tasks.RejectReportComputedTaskFactory.\
        with_task_failure
    TASK_ID_PROVIDER = 'task_failure'


class RejectReportComputedTaskSlotValidationTest(unittest.TestCase):
    FACTORY = factories.tasks.RejectReportComputedTaskFactory

    def test_validate_task_to_compute(self):
        msg = self.FACTORY.with_task_to_compute()
        msg2 = helpers.dump_and_load(msg)
        self.assertEqual(msg, msg2)

    def test_fail_task_to_compute(self):
        msg = self.FACTORY(attached_task_to_compute='blah')
        with self.assertRaises(exceptions.FieldError):
            helpers.dump_and_load(msg)

    def test_validate_cannot_compute_task(self):
        msg = self.FACTORY.with_cannot_compute_task()
        msg2 = helpers.dump_and_load(msg)
        self.assertEqual(msg, msg2)

    def test_fail_cannot_compute_task(self):
        msg = self.FACTORY(
            cannot_compute_task=factories.tasks.TaskToComputeFactory())
        with self.assertRaises(exceptions.FieldError):
            helpers.dump_and_load(msg)

    def test_validate_task_failure(self):
        msg = self.FACTORY.with_task_failure()
        msg2 = helpers.dump_and_load(msg)
        self.assertEqual(msg, msg2)

    def test_fail_task_failure(self):
        msg = self.FACTORY(
            task_failure=factories.tasks.TaskToComputeFactory())
        with self.assertRaises(exceptions.FieldError):
            helpers.dump_and_load(msg)
