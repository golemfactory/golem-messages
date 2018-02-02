# pylint: disable=no-self-use
import unittest
import unittest.mock as mock

from golem_messages import message

from tests import factories


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

class TasksTest(unittest.TestCase):
    def test_subtask_results_rejected_factory(self):
        msg = factories.SubtaskResultsRejectedFactory()
        self.assertIsInstance(msg, message.tasks.SubtaskResultsRejected)

    def test_subtask_results_rejected_fgtrf_factory(self):
        msg = factories.SubtaskResultsRejectedFGTRFFactory()
        self.assertIsInstance(msg, message.tasks.SubtaskResultsRejected)

    def test_subtask_results_rejected(self):
        rct = factories.ReportComputedTaskFactory()
        reason = message.tasks.SubtaskResultsRejected.REASON\
            .VerificationNegative
        msg = factories.SubtaskResultsRejectedFactory(
            slots__report_computed_task=rct,
            slots__reason=reason,
        )
        expected = [
            ['report_computed_task', rct],
            ['force_get_task_result_failed', None],
            ['reason', reason.value],
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.report_computed_task,
                              message.tasks.ReportComputedTask)

    def test_subtask_results_rejected_fgtrf(self):
        fgtrf = factories.ForceGetTaskResultFailedFactory()
        reason = message.tasks.SubtaskResultsRejected.REASON\
            .ForcedResourcesFailure
        msg = factories.SubtaskResultsRejectedFGTRFFactory(
            slots__force_get_task_result_failed=fgtrf,
            slots__reason=reason,
        )
        expected = [
            ['report_computed_task', None],
            ['force_get_task_result_failed', fgtrf],
            ['reason', reason.value],
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.force_get_task_result_failed,
                              message.concents.ForceGetTaskResultFailed)
