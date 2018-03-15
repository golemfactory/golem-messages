# pylint: disable=no-self-use
import unittest
import unittest.mock as mock

from golem_messages import exceptions
from golem_messages import message
from golem_messages import shortcuts

from tests import factories
from tests.message import mixins

class ComputeTaskDefTestCase(unittest.TestCase):
    @mock.patch('golem_messages.message.tasks.ComputeTaskDef.validate_task_id')
    def test_task_id_validator(self, v_mock):
        ctd = factories.ComputeTaskDefFactory()
        v_mock.assert_called_once_with(
            value=ctd['task_id'],
        )

    @mock.patch(
        'golem_messages.message.tasks.ComputeTaskDef.validate_subtask_id',
    )
    def test_subtask_id_validator(self, v_mock):
        ctd = factories.ComputeTaskDefFactory()
        v_mock.assert_called_once_with(
            value=ctd['subtask_id'],
        )


class SubtaskResultsAcceptedTest(mixins.RegisteredMessageTestMixin,
                                 mixins.SerializationMixin,
                                 mixins.TaskIdTaskToComputeTestMixin,
                                 unittest.TestCase):
    FACTORY = factories.SubtaskResultsAcceptedFactory
    MSG_CLASS = message.tasks.SubtaskResultsAccepted

    def test_factory(self):
        self.assertIsInstance(self.msg, message.tasks.SubtaskResultsAccepted)

    def test_task_to_compute_wrong_class(self):
        with self.assertRaises(exceptions.FieldError):
            message.tasks.SubtaskResultsAccepted(slots=(
                ('task_to_compute', 'something else'),
            ))

    def test_task_to_compute_correct(self):
        msg = message.tasks.SubtaskResultsAccepted(slots=(
            ('task_to_compute', factories.TaskToComputeFactory()),
        ))
        self.assertIsInstance(msg.task_to_compute, message.tasks.TaskToCompute)


class SubtaskResultsRejectedTest(mixins.RegisteredMessageTestMixin,
                                 mixins.SerializationMixin,
                                 mixins.TaskIdReportComputedTaskTestMixin,
                                 unittest.TestCase):
    FACTORY = factories.SubtaskResultsRejectedFactory
    MSG_CLASS = message.tasks.SubtaskResultsRejected

    def test_subtask_results_rejected_factory(self):
        msg = factories.SubtaskResultsRejectedFactory()
        self.assertIsInstance(msg, message.tasks.SubtaskResultsRejected)

    def test_subtask_results_rejected(self):
        rct = factories.ReportComputedTaskFactory()
        reason = message.tasks.SubtaskResultsRejected.REASON\
            .VerificationNegative
        msg = factories.SubtaskResultsRejectedFactory(
            report_computed_task=rct,
            reason=reason,
        )
        expected = [
            ['report_computed_task', rct],
            ['reason', reason.value],
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.report_computed_task,
                              message.tasks.ReportComputedTask)


class TaskToComputeTest(mixins.RegisteredMessageTestMixin,
                        mixins.SerializationMixin,
                        unittest.TestCase, ):
    FACTORY = factories.TaskToComputeFactory
    MSG_CLASS = message.tasks.TaskToCompute

    def setUp(self):
        self.msg = self.FACTORY()

    def test_task_to_compute_basic(self):
        ttc = factories.TaskToComputeFactory()
        serialized = shortcuts.dump(ttc, None, None)
        msg = shortcuts.load(serialized, None, None)
        self.assertIsInstance(msg, message.tasks.TaskToCompute)

    def test_concent_enabled_attribute(self):
        ttc = factories.TaskToComputeFactory(concent_enabled=True)
        self.assertTrue(ttc.concent_enabled)

    def test_concent_enabled_default_true(self):
        ttc = message.tasks.TaskToCompute()
        self.assertTrue(ttc.concent_enabled)

    def test_concent_enabled_false(self):
        ttc = message.tasks.TaskToCompute(concent_enabled=False)
        self.assertFalse(ttc.concent_enabled)

    def test_ethereum_address(self):
        msg = factories.TaskToComputeFactory()
        serialized = shortcuts.dump(msg, None, None)
        msg_l = shortcuts.load(serialized, None, None)
        for addr_slot in (
                'requestor_ethereum_address',
                'provider_ethereum_address'):
            address = getattr(msg_l, addr_slot)
            self.assertEqual(len(address), 2 + (20*2))

    def test_task_id(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.compute_task_def['task_id'])

    def test_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.compute_task_def['subtask_id'])


class ReportComputedTaskTest(mixins.RegisteredMessageTestMixin,
                             mixins.SerializationMixin,
                             unittest.TestCase):
    FACTORY = factories.ReportComputedTaskFactory
    MSG_CLASS = message.tasks.ReportComputedTask

    def setUp(self):
        self.msg = self.FACTORY()

    def test_task_id(self):
        self.assertEqual(self.msg.task_id, self.msg.task_to_compute.task_id)

    def test_factory_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.task_to_compute.subtask_id)
