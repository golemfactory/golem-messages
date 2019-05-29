import unittest

from golem_messages import factories
from golem_messages import message
from tests.message import mixins


class TaskFailureTest(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = message.tasks.TaskFailure
    FACTORY = factories.tasks.TaskFailureFactory
    TASK_ID_PROVIDER = 'task_to_compute'
