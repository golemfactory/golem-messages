import unittest

from golem_messages import exceptions
from golem_messages import factories
from golem_messages import message
from tests.message import mixins, helpers


class SubtaskResultsRejectedTest(mixins.RegisteredMessageTestMixin,
                                 mixins.SerializationMixin,
                                 mixins.TaskIdMixin,
                                 unittest.TestCase):
    FACTORY = factories.tasks.SubtaskResultsRejectedFactory
    MSG_CLASS = message.tasks.SubtaskResultsRejected
    TASK_ID_PROVIDER = 'report_computed_task'

    def srr_with_fgtrf(self):
        msg = self.FACTORY(
            report_computed_task__task_to_compute__concent_enabled=True,
            reason=message.tasks.SubtaskResultsRejected.REASON.
            ForcedResourcesFailure,
        )
        msg.force_get_task_result_failed = \
            factories.concents.ForceGetTaskResultFailedFactory(
                task_to_compute=helpers.dump_and_load(
                    msg.report_computed_task.task_to_compute
                )
            )
        return msg

    def test_factory(self):
        msg = self.FACTORY()
        self.assertIsInstance(msg, self.MSG_CLASS)

    def test_message(self):
        rct = factories.tasks.ReportComputedTaskFactory()
        reason = message.tasks.SubtaskResultsRejected.REASON\
            .VerificationNegative
        msg = factories.tasks.SubtaskResultsRejectedFactory(
            report_computed_task=rct,
            reason=reason,
        )
        expected = [
            ['report_computed_task', helpers.single_nested(rct)],
            ['force_get_task_result_failed', (False, None)],
            ['reason', reason.value],
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.report_computed_task,
                              message.tasks.ReportComputedTask)
        self.assertTrue(msg.is_valid())

    def test_message_invalid_no_reason(self):
        msg = self.FACTORY(reason=None)
        with self.assertRaises(exceptions.ValidationError):
            msg.is_valid()

    def test_message_valid_with_fgtrf(self):
        msg = self.srr_with_fgtrf()
        self.assertTrue(msg.is_valid)

    def test_message_invalid_different_fgtrf_task(self):
        msg = self.srr_with_fgtrf()
        msg.force_get_task_result_failed.\
            task_to_compute.compute_task_def['task_id'] = '667'
        with self.assertRaises(exceptions.ValidationError):
            msg.is_valid()

    def test_message_invalid_different_fgtrf_subtask(self):
        msg = self.srr_with_fgtrf()
        msg.force_get_task_result_failed.\
            task_to_compute.compute_task_def['subtask_id'] = '667'
        with self.assertRaises(exceptions.ValidationError):
            msg.is_valid()

    def test_message_invalid_forced_resources_failure_without_fgtrf(self):
        msg = self.FACTORY(
            reason=self.MSG_CLASS.REASON.ForcedResourcesFailure
        )
        with self.assertRaises(exceptions.ValidationError):
            msg.is_valid()

    def test_requestor_valid_reasons_no_concent(self):
        for reason in (
                self.MSG_CLASS.REASON.VerificationNegative,
                self.MSG_CLASS.REASON.ResourcesFailure,
        ):
            msg = self.FACTORY(reason=reason)
            self.assertTrue(msg.is_valid_for_requestor())

    def test_requestor_invalid_reasons_no_concent(self):
        for reason in (
                self.MSG_CLASS.REASON.ForcedResourcesFailure,
                self.MSG_CLASS.REASON.ConcentResourcesFailure,
                self.MSG_CLASS.REASON.ConcentVerificationNegative,
        ):
            msg = self.FACTORY(reason=reason)
            with self.assertRaises(
                exceptions.ValidationError,
                msg=f"Validation error not raised for {reason}"
            ):
                msg.is_valid_for_requestor()

    def test_requestor_valid_reasons_with_concent(self):
        for reason in (
                self.MSG_CLASS.REASON.VerificationNegative,
        ):
            msg = self.FACTORY(
                reason=reason,
                report_computed_task__task_to_compute__concent_enabled=True,
            )
            self.assertTrue(msg.is_valid_for_requestor())

    def test_requestor_valid_forced_resources_failure_with_concent(self):
        msg = self.srr_with_fgtrf()
        self.assertEqual(
            msg.reason, self.MSG_CLASS.REASON.ForcedResourcesFailure)
        self.assertTrue(msg.is_valid_for_requestor())

    def test_requestor_invalid_reasons_with_concent(self):
        for reason in (
                self.MSG_CLASS.REASON.ResourcesFailure,
                self.MSG_CLASS.REASON.ConcentResourcesFailure,
                self.MSG_CLASS.REASON.ConcentVerificationNegative,
        ):
            msg = self.FACTORY(
                report_computed_task__task_to_compute__concent_enabled=True,
                reason=reason
            )
            with self.assertRaises(
                exceptions.ValidationError,
                msg=f"Validation error not raised for {reason}"
            ):
                msg.is_valid_for_requestor()
