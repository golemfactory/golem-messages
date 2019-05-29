import unittest

from golem_messages import factories
from golem_messages import message
from tests.message import mixins


class WaitingForResultsTest(
        mixins.RegisteredMessageTestMixin,
        mixins.SerializationMixin,
        mixins.TaskIdMixin,
        unittest.TestCase):
    FACTORY = factories.tasks.WaitingForResultsFactory
    MSG_CLASS = message.tasks.WaitingForResults
    TASK_ID_PROVIDER = 'task_to_compute'
