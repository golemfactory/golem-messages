import unittest

from golem_messages import message
from golem_messages.message import concents

from tests import factories

class ConcentsTest(unittest.TestCase):

    def test_subtask_result_verify(self):
        srr = factories.SubtaskResultsRejectedFactory()
        msg = factories.SubtaskResultsVerifyFactory(
            slots__subtask_result_rejected=srr,
        )
        expected = [
            ['subtask_result_rejected', srr]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.subtask_result_rejected,
                              message.tasks.SubtaskResultsRejected)

    def test_ack_subtask_result_verify(self):
        srv = factories.SubtaskResultsVerifyFactory()
        msg = factories.AckSubtaskResultsVerifyFactory(
            slots__subtask_results_verify=srv,
        )
        expected = [
            ['subtask_result_verify', srv]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.subtask_result_verify,
                              concents.SubtaskResultsVerify)

    def test_subtask_result_settled_no_acceptance(self):
        ttc = factories.TaskToComputeFactory()
        msg = factories.SubtaskResultsSettledFactory.origin_acceptance_timeout(
            slots__task_to_compute=ttc
        )
        expected = [
            ['origin',
             concents.SubtaskResultsSettled.Origin.ResultsAcceptedTimeout
             .value],
            ['task_to_compute', ttc]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.task_to_compute, message.tasks.TaskToCompute)

    def test_subtask_result_settled_results_rejected(self):
        ttc = factories.TaskToComputeFactory()
        msg = factories.SubtaskResultsSettledFactory.origin_results_rejected(
            slots__task_to_compute=ttc
        )
        expected = [
            ['origin',
             concents.SubtaskResultsSettled.Origin.ResultsRejected.value],
            ['task_to_compute', ttc]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.task_to_compute, message.tasks.TaskToCompute)

    def test_force_get_task_result(self):
        rct = factories.ReportComputedTaskFactory()
        frct = factories.ForceReportComputedTaskFactory()
        msg = factories.ForceGetTaskResultFactory(
            slots__report_computed_task=rct,
            slots__force_report_computed_task=frct
        )
        expected = [
            ['report_computed_task', rct],
            ['force_report_computed_task', frct]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.report_computed_task,
                              message.tasks.ReportComputedTask)
        self.assertIsInstance(msg.force_report_computed_task,
                              message.concents.ForceReportComputedTask)

    def test_force_get_task_result_ack(self):
        fgtr = factories.ForceGetTaskResultFactory()
        msg = factories.ForceGetTaskResultAckFactory(
            slots__force_get_task_result=fgtr
        )
        expected = [
            ['force_get_task_result', fgtr]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.force_get_task_result,
                              message.concents.ForceGetTaskResult)

    def test_force_get_task_result_failed(self):
        ttc = factories.TaskToComputeFactory()
        msg = factories.ForceGetTaskResultFailedFactory(
            slots__task_to_compute=ttc
        )
        expected = [
            ['task_to_compute', ttc]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.task_to_compute, message.tasks.TaskToCompute)

    def test_force_get_task_result_rejected(self):
        fgtr = factories.ForceGetTaskResultFactory()
        msg = factories.ForceGetTaskResultRejectedFactory(
            slots__force_get_task_result=fgtr
        )
        expected = [
            ['force_get_task_result', fgtr],
            ['reason', None]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.force_get_task_result,
                              message.concents.ForceGetTaskResult)

    def test_force_get_task_result_upload(self):
        fgtr = factories.ForceGetTaskResultFactory()
        ftt = message.concents.FileTransferToken()
        msg = factories.ForceGetTaskResultUploadFactory(
            slots__force_get_task_result=fgtr,
            slots__file_transfer_token=ftt
        )
        expected = [
            ['force_get_task_result', fgtr],
            ['file_transfer_token', ftt]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.force_get_task_result,
                              message.concents.ForceGetTaskResult)
        self.assertIsInstance(msg.file_transfer_token,
                              message.concents.FileTransferToken)

    def test_force_get_task_result_download(self):
        fgtr = factories.ForceGetTaskResultFactory()
        ftt = message.concents.FileTransferToken()
        msg = factories.ForceGetTaskResultDownloadFactory(
            slots__force_get_task_result=fgtr,
            slots__file_transfer_token=ftt
        )
        expected = [
            ['force_get_task_result', fgtr],
            ['file_transfer_token', ftt]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.force_get_task_result,
                              message.concents.ForceGetTaskResult)
        self.assertIsInstance(msg.file_transfer_token,
                              message.concents.FileTransferToken)

    def test_force_subtask_results(self):
        ack_rct = factories.AckReportComputedTaskFactory()

        msg = factories.ForceSubtaskResultsFactory(
            ack_report_computed_task=ack_rct,
        )

        expected = [
            ['ack_report_computed_task', ack_rct]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.ack_report_computed_task,
                              message.concents.AckReportComputedTask)
