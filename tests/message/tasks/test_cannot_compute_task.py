import unittest

from golem_messages import factories
from golem_messages import message

from tests.message import mixins


class CannotComputeTaskTest(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = message.tasks.CannotComputeTask
    FACTORY = factories.tasks.CannotComputeTaskFactory
    TASK_ID_PROVIDER = 'task_to_compute'

    def test_factory_default_reason(self):
        msg = self.FACTORY()
        self.assertIsNotNone(msg.reason)
