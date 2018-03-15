import unittest

from golem_messages import exceptions
from golem_messages import message

from golem_messages.message import concents

from tests import factories
from tests.message import mixins

class ServiceRefusedTest(mixins.RegisteredMessageTestMixin,
                         mixins.SerializationMixin,
                         mixins.TaskIdTaskToComputeTestMixin,
                         unittest.TestCase):
    FACTORY = factories.ServiceRefusedFactory
    MSG_CLASS = concents.ServiceRefused


class FileTranferTokenTest(mixins.RegisteredMessageTestMixin,
                           unittest.TestCase):
    MSG_CLASS = concents.FileTransferToken

    def test_operation_upload(self):
        ftt = concents.FileTransferToken(slots=(
            ('operation', concents.FileTransferToken.Operation.upload),
        ))
        self.assertEqual(dict(ftt.slots()).get('operation'),
                         concents.FileTransferToken.Operation.upload.value)

    def test_operation_download(self):
        ftt = concents.FileTransferToken(slots=(
            ('operation', concents.FileTransferToken.Operation.download),
        ))
        self.assertEqual(dict(ftt.slots()).get('operation'),
                         concents.FileTransferToken.Operation.download.value)

    def test_operation_other(self):
        with self.assertRaises(exceptions.FieldError):
            concents.FileTransferToken(slots=(
                ('operation', 'other'),
            ))


class SubtaskResultsVerifyTest(mixins.RegisteredMessageTestMixin,
                               mixins.SerializationMixin,
                               unittest.TestCase):
    FACTORY = factories.SubtaskResultsVerifyFactory
    MSG_CLASS = concents.SubtaskResultsVerify

    def setUp(self):
        self.msg = self.FACTORY()

    def test_subtask_results_verify(self):
        srr = factories.SubtaskResultsRejectedFactory()
        msg = self.FACTORY(
            subtask_results_rejected=srr,
        )
        expected = [
            ['subtask_results_rejected', srr]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.subtask_results_rejected,
                              message.tasks.SubtaskResultsRejected)

    def test_task_id(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.subtask_results_rejected.task_id)

    def test_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.subtask_results_rejected.subtask_id)


class AckSubtaskResultsVerifyTest(mixins.RegisteredMessageTestMixin,
                                  mixins.SerializationMixin,
                                  unittest.TestCase):
    FACTORY = factories.AckSubtaskResultsVerifyFactory
    MSG_CLASS = concents.AckSubtaskResultsVerify

    def setUp(self):
        self.msg = self.FACTORY()

    def test_ack_subtask_results_verify(self):
        srv = factories.SubtaskResultsVerifyFactory()
        ftt = factories.FileTransferTokenFactory()
        msg = self.FACTORY(
            subtask_results_verify=srv,
            file_transfer_token=ftt,
        )
        expected = [
            ['subtask_results_verify', srv],
            ['file_transfer_token', ftt]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.subtask_results_verify,
                              concents.SubtaskResultsVerify)
        self.assertIsInstance(msg.file_transfer_token,
                              concents.FileTransferToken)

    def test_task_id(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.subtask_results_verify.task_id)

    def test_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.subtask_results_verify.subtask_id)


class SubtaskResultsSettledTest(mixins.RegisteredMessageTestMixin,
                                mixins.SerializationMixin,
                                mixins.TaskIdTaskToComputeTestMixin,
                                unittest.TestCase):
    FACTORY = factories.SubtaskResultsSettledFactory
    MSG_CLASS = concents.SubtaskResultsSettled

    def test_subtask_result_settled_no_acceptance(self):
        ttc = factories.TaskToComputeFactory()
        msg = factories.SubtaskResultsSettledFactory.origin_acceptance_timeout(
            task_to_compute=ttc
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
            task_to_compute=ttc
        )
        expected = [
            ['origin',
             concents.SubtaskResultsSettled.Origin.ResultsRejected.value],
            ['task_to_compute', ttc]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.task_to_compute, message.tasks.TaskToCompute)


class ForceGetTaskResultTest(mixins.RegisteredMessageTestMixin,
                             mixins.SerializationMixin,
                             mixins.TaskIdReportComputedTaskTestMixin,
                             unittest.TestCase):
    FACTORY = factories.ForceGetTaskResultFactory
    MSG_CLASS = message.concents.ForceGetTaskResult

    def test_force_get_task_result(self):
        rct = factories.ReportComputedTaskFactory()
        msg = self.FACTORY(
            report_computed_task=rct,
        )
        expected = [
            ['report_computed_task', rct],
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.report_computed_task,
                              message.tasks.ReportComputedTask)


class AckForceGetTaskResultTest(mixins.RegisteredMessageTestMixin,
                                mixins.SerializationMixin,
                                mixins.TaskIdForceGetTaskResultTestMixin,
                                unittest.TestCase):
    FACTORY = factories.AckForceGetTaskResultFactory
    MSG_CLASS = message.concents.AckForceGetTaskResult

    def test_ack_force_get_task_result(self):
        fgtr = factories.ForceGetTaskResultFactory()
        msg = factories.AckForceGetTaskResultFactory(
            force_get_task_result=fgtr
        )
        expected = [
            ['force_get_task_result', fgtr]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.force_get_task_result,
                              message.concents.ForceGetTaskResult)


class ForceGetTaskResultFailedTest(mixins.RegisteredMessageTestMixin,
                                   mixins.SerializationMixin,
                                   mixins.TaskIdTaskToComputeTestMixin,
                                   unittest.TestCase):
    FACTORY = factories.ForceGetTaskResultFailedFactory
    MSG_CLASS = message.concents.ForceGetTaskResultFailed

    def test_force_get_task_result_failed(self):
        ttc = factories.TaskToComputeFactory()
        msg = factories.ForceGetTaskResultFailedFactory(
            task_to_compute=ttc
        )
        expected = [
            ['task_to_compute', ttc]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.task_to_compute, message.tasks.TaskToCompute)


class ForceGetTaskResultRejectedTest(mixins.RegisteredMessageTestMixin,
                                     mixins.SerializationMixin,
                                     mixins.TaskIdForceGetTaskResultTestMixin,
                                     unittest.TestCase):
    FACTORY = factories.ForceGetTaskResultRejectedFactory
    MSG_CLASS = message.concents.ForceGetTaskResultRejected

    def test_force_get_task_result_rejected(self):
        fgtr = factories.ForceGetTaskResultFactory()
        msg = factories.ForceGetTaskResultRejectedFactory(
            force_get_task_result=fgtr
        )
        expected = [
            ['force_get_task_result', fgtr],
            ['reason', None]
        ]

        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(msg.force_get_task_result,
                              message.concents.ForceGetTaskResult)


class ForceGetTaskResultUploadTest(mixins.RegisteredMessageTestMixin,
                                   mixins.SerializationMixin,
                                   mixins.TaskIdForceGetTaskResultTestMixin,
                                   unittest.TestCase):
    FACTORY = factories.ForceGetTaskResultUploadFactory
    MSG_CLASS = message.concents.ForceGetTaskResultUpload

    def test_force_get_task_result_upload(self):
        fgtr = factories.ForceGetTaskResultFactory()
        ftt = message.concents.FileTransferToken()
        msg = factories.ForceGetTaskResultUploadFactory(
            force_get_task_result=fgtr,
            file_transfer_token=ftt
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


class ForceGetTaskResultDownloadTest(mixins.RegisteredMessageTestMixin,
                                     mixins.SerializationMixin,
                                     mixins.TaskIdForceGetTaskResultTestMixin,
                                     unittest.TestCase):
    FACTORY = factories.ForceGetTaskResultDownloadFactory
    MSG_CLASS = message.concents.ForceGetTaskResultDownload

    def test_force_get_task_result_download(self):
        fgtr = factories.ForceGetTaskResultFactory()
        ftt = message.concents.FileTransferToken()
        msg = factories.ForceGetTaskResultDownloadFactory(
            force_get_task_result=fgtr,
            file_transfer_token=ftt
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


class ForceSubtaskResultsTest(mixins.RegisteredMessageTestMixin,
                              mixins.SerializationMixin,
                              mixins.TaskIdAckReportComputedTaskTestMixin,
                              unittest.TestCase):
    FACTORY = factories.ForceSubtaskResultsFactory
    MSG_CLASS = concents.ForceSubtaskResults

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


class ForceSubtaskResultsResponseTest(mixins.RegisteredMessageTestMixin,
                                      mixins.SerializationMixin,
                                      unittest.TestCase):
    FACTORY = factories.ForceSubtaskResultsResponseFactory
    MSG_CLASS = concents.ForceSubtaskResultsResponse

    def test_force_subtask_results_response_accepted(self):
        subtask_results_accepted = factories.SubtaskResultsAcceptedFactory()
        msg = factories.ForceSubtaskResultsResponseFactory(
            subtask_results_accepted=subtask_results_accepted
        )
        expected = [
            ['subtask_results_accepted', subtask_results_accepted],
            ['subtask_results_rejected', None],
        ]
        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(
            msg.subtask_results_accepted,
            message.tasks.SubtaskResultsAccepted
        )

    def test_force_subtask_results_response_accepted_subfactory(self):
        msg = factories.ForceSubtaskResultsResponseFactory.with_accepted()
        self.assertIsInstance(
            msg.subtask_results_accepted,
            message.tasks.SubtaskResultsAccepted
        )

    def test_force_subtask_results_response_rejected(self):
        subtask_results_rejected = factories.SubtaskResultsRejectedFactory()
        msg = factories.ForceSubtaskResultsResponseFactory(
            subtask_results_rejected=subtask_results_rejected
        )
        expected = [
            ['subtask_results_accepted', None],
            ['subtask_results_rejected', subtask_results_rejected],
        ]
        self.assertEqual(expected, msg.slots())
        self.assertIsInstance(
            msg.subtask_results_rejected,
            message.tasks.SubtaskResultsRejected
        )

    def test_force_subtask_results_response_rejected_subfactory(self):
        msg = factories.ForceSubtaskResultsResponseFactory.with_rejected()
        self.assertIsInstance(
            msg.subtask_results_rejected,
            message.tasks.SubtaskResultsRejected
        )

    def test_force_subtask_results_response_deserialize_accepted(self):
        subtask_results_accepted = factories.SubtaskResultsAcceptedFactory()
        msg = concents.ForceSubtaskResultsResponse(slots=(
            ('subtask_results_accepted', subtask_results_accepted),
        ))
        self.assertIsInstance(
            msg.subtask_results_accepted,
            message.tasks.SubtaskResultsAccepted
        )

    def test_force_subtask_results_response_fail_accepted(self):
        with self.assertRaises(exceptions.FieldError):
            concents.ForceSubtaskResultsResponse(slots=(
                ('subtask_results_accepted', 'loonquawl'),
            ))

    def test_force_subtask_results_response_deserialize_rejected(self):
        subtask_results_rejected = factories.SubtaskResultsRejectedFactory()
        msg = concents.ForceSubtaskResultsResponse(slots=(
            ('subtask_results_rejected', subtask_results_rejected),
        ))
        self.assertIsInstance(
            msg.subtask_results_rejected,
            message.tasks.SubtaskResultsRejected
        )

    def test_force_subtask_results_response_fail_rejected(self):
        with self.assertRaises(exceptions.FieldError):
            concents.ForceSubtaskResultsResponse(slots=(
                ('subtask_results_rejected', 'phouchg'),
            ))

    def test_task_id_srr(self):
        msg = self.FACTORY.with_rejected()
        self.assertEqual(msg.task_id,
                         msg.subtask_results_rejected.task_id)

    def test_subtask_id_srr(self):
        msg = self.FACTORY.with_rejected()
        self.assertEqual(msg.subtask_id,
                         msg.subtask_results_rejected.subtask_id)

    def test_task_id_sra(self):
        msg = self.FACTORY.with_accepted()
        self.assertEqual(msg.task_id,
                         msg.subtask_results_accepted.task_id)

    def test_subtask_id_sra(self):
        msg = self.FACTORY.with_accepted()
        self.assertEqual(msg.subtask_id,
                         msg.subtask_results_accepted.subtask_id)


class ForceSubtaskResultsRejectedTest(mixins.RegisteredMessageTestMixin,
                                      unittest.TestCase):
    MSG_CLASS = concents.ForceSubtaskResultsRejected

    def test_force_subtask_results_premature(self):
        msg = factories.ForceSubtaskResultsRejectedFactory.premature()
        self.assertEqual(
            msg.reason,
            concents.ForceSubtaskResultsRejected.REASON.RequestPremature
        )

    def test_force_subtask_results_toolate(self):
        msg = factories.ForceSubtaskResultsRejectedFactory.too_late()
        self.assertEqual(
            msg.reason,
            concents.ForceSubtaskResultsRejected.REASON.RequestTooLate
        )


class ForcePaymentTest(mixins.RegisteredMessageTestMixin, unittest.TestCase):
    MSG_CLASS = concents.ForcePayment

    def test_factory(self):
        msg = factories.ForcePaymentFactory()
        self.assertIsInstance(msg, self.MSG_CLASS)

    def test_factory_generate_list(self):
        msg = factories.ForcePaymentFactory.with_accepted_tasks()
        self.assertIsInstance(msg.subtask_results_accepted_list, list)
        self.assertIsInstance(
            msg.subtask_results_accepted_list[0],  # noqa pylint:disable=unsubscriptable-object
            message.tasks.SubtaskResultsAccepted)

    def test_factory_list_provided(self):
        msg = factories.ForcePaymentFactory(
            subtask_results_accepted_list=[
                factories.SubtaskResultsAcceptedFactory()
            ])
        self.assertIsInstance(msg.subtask_results_accepted_list, list)
        self.assertIsInstance(
            msg.subtask_results_accepted_list[0],  # noqa pylint:disable=unsubscriptable-object
            message.tasks.SubtaskResultsAccepted)

    def test_sra_list_verify(self):
        msg = concents.ForcePayment(slots=[
            ('subtask_results_accepted_list', [
                factories.SubtaskResultsAcceptedFactory()
            ]),
        ])
        self.assertIsInstance(msg.subtask_results_accepted_list[0],
                              message.tasks.SubtaskResultsAccepted)

    def test_sra_list_wrong_class(self):
        with self.assertRaises(exceptions.FieldError):
            concents.ForcePayment(slots=[
                ('subtask_results_accepted_list', [message.base.Message()]),
            ])


class ForcePaymentCommittedTest(mixins.RegisteredMessageTestMixin,
                                unittest.TestCase):
    MSG_CLASS = concents.ForcePaymentCommitted

    def test_factory(self):
        msg = factories.ForcePaymentCommittedFactory()
        self.assertIsInstance(msg, self.MSG_CLASS)

    def test_factory_to_provider(self):
        msg = factories.ForcePaymentCommittedFactory.to_provider()
        self.assertEqual(msg.recipient_type,
                         concents.ForcePaymentCommitted.Actor.Provider)

    def test_factory_to_requestor(self):
        msg = factories.ForcePaymentCommittedFactory.to_requestor()
        self.assertEqual(msg.recipient_type,
                         concents.ForcePaymentCommitted.Actor.Requestor)


class ForcePaymentRejectedTest(mixins.RegisteredMessageTestMixin,
                               unittest.TestCase):
    MSG_CLASS = concents.ForcePaymentRejected

    def test_factory(self):
        msg = factories.ForcePaymentRejectedFactory()
        self.assertIsInstance(msg, self.MSG_CLASS)

    def test_force_payment(self):
        msg = concents.ForcePaymentRejected(slots=[
            ('force_payment', factories.ForcePaymentFactory())
        ])
        self.assertIsInstance(msg.force_payment, concents.ForcePayment)

    def test_force_payment_wrong_class(self):
        with self.assertRaises(exceptions.FieldError):
            concents.ForcePaymentRejected(slots=[
                ('force_payment', message.base.Message())
            ])


class ForceReportComputedTaskTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdReportComputedTaskTestMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = concents.ForceReportComputedTask
    FACTORY = factories.ForceReportComputedTaskFactory


class ForceReportComputedTaskResponseTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = concents.ForceReportComputedTaskResponse
    FACTORY = factories.ForceReportComputedTaskResponseFactory

    def setUp(self):
        self.msg = self.FACTORY()

    def test_task_id_ack(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.ack_report_computed_task.task_id)

    def test_subtask_id_ack(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.ack_report_computed_task.subtask_id)

    def test_task_id_reject(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.reject_report_computed_task.task_id)

    def test_subtask_id_reject(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.reject_report_computed_task.subtask_id)


class AckReportComputedTaskTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdTaskToComputeTestMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = concents.AckReportComputedTask
    FACTORY = factories.AckReportComputedTaskFactory


class RejectReportComputedTaskTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdTaskToComputeTestMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = concents.RejectReportComputedTask
    FACTORY = factories.RejectReportComputedTaskFactory


class VerdictReportComputeTaskTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = concents.VerdictReportComputedTask
    FACTORY = factories.VerdictReportComputedTaskFactory

    def setUp(self):
        self.msg = self.FACTORY()

    def test_task_id(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.ack_report_computed_task.task_id)

    def test_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.ack_report_computed_task.subtask_id)

    def test_task_id_frct(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.force_report_computed_task.task_id)

    def test_subtask_id_frct(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.force_report_computed_task.subtask_id)


class ClientAuthorizationTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = concents.ClientAuthorization
    FACTORY = factories.ClientAuthorizationFactory
