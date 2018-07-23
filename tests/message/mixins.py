# pylint: disable=protected-access
import golem_messages
from golem_messages import message
from golem_messages.register import library

# pylint: disable=too-few-public-methods


class RegisteredMessageTestMixin():
    MSG_CLASS = None

    def test_registered(self):
        self.assertIn(self.MSG_CLASS,
                      library._reversed)

# pylint: enable=too-few-public-methods


class SerializationMixin():

    def get_instance(self):
        return self.FACTORY()

    def test_serialization(self):
        msg = self.get_instance()
        s_msg = golem_messages.dump(msg, None, None)
        msg2 = golem_messages.load(s_msg, None, None)
        self.assertEqual(msg, msg2)


class TaskIdMixin:
    TASK_ID_PROVIDER = None

    @property
    def task_id_provider(self):
        return getattr(self.msg, self.TASK_ID_PROVIDER)

    def setUp(self):
        self.msg = self.FACTORY()

    def test_task_id(self):
        self.assertEqual(self.msg.task_id, self.task_id_provider.task_id)

    def test_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.task_id_provider.subtask_id)

    def test_ttc(self):
        self.assertEqual(
            self.msg.task_to_compute, self.task_id_provider.task_to_compute)
        self.assertIsInstance(
            self.msg.task_to_compute, message.tasks.TaskToCompute)

    def test_provider_id(self):
        self.assertEqual(self.msg.provider_id,
                         self.task_id_provider.provider_id)
        self.assertEqual(self.msg.provider_id,
                         self.msg.task_to_compute.provider_id)

    def test_requestor_id(self):
        self.assertEqual(self.msg.requestor_id,
                         self.task_id_provider.requestor_id)
        self.assertEqual(self.msg.requestor_id,
                         self.msg.task_to_compute.requestor_id)
