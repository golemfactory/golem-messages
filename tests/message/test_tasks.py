# pylint: disable=no-self-use
import unittest
import unittest.mock as mock

from golem_messages import exceptions
from golem_messages import message
from golem_messages import shortcuts

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

class TaskToComputeTest(unittest.TestCase):
    def test_task_to_compute_basic(self):
        ttc = factories.TaskToComputeFactory()
        serialized = shortcuts.dump(ttc, None, None)
        msg = shortcuts.load(serialized, None, None)
        self.assertIsInstance(msg, message.tasks.TaskToCompute)

    def test_task_to_compute_validate_compute_task_def(self):
        requestor_id = 'such as epidemiology'
        # Shoudn't raise
        message.TaskToCompute(slots=(
            ('requestor_id', requestor_id),
        ))

        compute_task_def = message.ComputeTaskDef(
            task_owner={'key': requestor_id}
        )
        message.TaskToCompute(slots=(
            ('requestor_id', requestor_id),
            ('compute_task_def', compute_task_def),
        ))

        with self.assertRaises(exceptions.FieldError):
            message.TaskToCompute(slots=(
                ('requestor_id', 'staple of research'),
                ('compute_task_def', compute_task_def),
            ))

    def test_concent_enabled(self):
        ttc = factories.TaskToComputeFactory(concent_enabled=True)
        self.assertTrue(ttc.concent_enabled)
