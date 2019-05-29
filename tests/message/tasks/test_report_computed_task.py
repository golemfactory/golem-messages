import unittest

from golem_messages import factories
from golem_messages import message

from tests.message import mixins


class ReportComputedTaskTest(mixins.RegisteredMessageTestMixin,
                             mixins.SerializationMixin,
                             unittest.TestCase):
    FACTORY = factories.tasks.ReportComputedTaskFactory
    MSG_CLASS = message.tasks.ReportComputedTask

    def setUp(self):
        self.msg = self.FACTORY()

    def test_task_id(self):
        self.assertEqual(self.msg.task_id, self.msg.task_to_compute.task_id)

    def test_factory_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.task_to_compute.subtask_id)
