import golem_messages
from golem_messages import message

# pylint: disable=too-few-public-methods


class RegisteredMessageTestMixin():
    MSG_CLASS = None

    def test_registered(self):
        self.assertIn(self.MSG_CLASS,
                      message.registered_message_types.values())

# pylint: enable=too-few-public-methods


class SerializationMixin():

    def get_instance(self):
        return self.FACTORY()

    def test_serialization(self):
        msg = self.get_instance()
        s_msg = golem_messages.dump(msg, None, None)
        msg2 = golem_messages.load(s_msg, None, None)
        self.assertEqual(msg, msg2)


class TaskIdMixinBase():
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


class TaskIdTaskToComputeTestMixin(TaskIdMixinBase):
    TASK_ID_PROVIDER = 'task_to_compute'


class TaskIdReportComputedTaskTestMixin(TaskIdMixinBase):
    TASK_ID_PROVIDER = 'report_computed_task'


class TaskIdForceGetTaskResultTestMixin(TaskIdMixinBase):
    TASK_ID_PROVIDER = 'force_get_task_result'


class TaskIdAckReportComputedTaskTestMixin(TaskIdMixinBase):
    TASK_ID_PROVIDER = 'ack_report_computed_task'
