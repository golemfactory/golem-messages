# pylint: disable=no-self-use
import calendar
import time
import unittest
import unittest.mock as mock

from golem_messages import cryptography
from golem_messages import exceptions
from golem_messages import factories
from golem_messages import message
from golem_messages import shortcuts

from tests.message import mixins


class ComputeTaskDefTestCase(unittest.TestCase):
    @mock.patch('golem_messages.message.tasks.ComputeTaskDef.validate_task_id')
    def test_task_id_validator(self, v_mock):
        ctd = factories.tasks.ComputeTaskDefFactory()
        v_mock.assert_called_once_with(
            value=ctd['task_id'],
        )

    @mock.patch(
        'golem_messages.message.tasks.ComputeTaskDef.validate_subtask_id',
    )
    def test_subtask_id_validator(self, v_mock):
        ctd = factories.tasks.ComputeTaskDefFactory()
        v_mock.assert_called_once_with(
            value=ctd['subtask_id'],
        )


class SubtaskResultsAcceptedTest(mixins.RegisteredMessageTestMixin,
                                 mixins.SerializationMixin,
                                 mixins.TaskIdMixin,
                                 unittest.TestCase):
    FACTORY = factories.tasks.SubtaskResultsAcceptedFactory
    MSG_CLASS = message.tasks.SubtaskResultsAccepted
    TASK_ID_PROVIDER = 'task_to_compute'

    def test_factory(self):
        self.assertIsInstance(self.msg, message.tasks.SubtaskResultsAccepted)

    def test_task_to_compute_wrong_class(self):
        with self.assertRaises(exceptions.FieldError):
            message.tasks.SubtaskResultsAccepted(slots=(
                ('task_to_compute', 'something else'),
            ))

    def test_task_to_compute_correct(self):
        msg = message.tasks.SubtaskResultsAccepted(slots=(
            ('task_to_compute', factories.tasks.TaskToComputeFactory()),
        ))
        self.assertIsInstance(msg.task_to_compute, message.tasks.TaskToCompute)


class SubtaskResultsRejectedTest(mixins.RegisteredMessageTestMixin,
                                 mixins.SerializationMixin,
                                 mixins.TaskIdMixin,
                                 unittest.TestCase):
    FACTORY = factories.tasks.SubtaskResultsRejectedFactory
    MSG_CLASS = message.tasks.SubtaskResultsRejected
    TASK_ID_PROVIDER = 'report_computed_task'

    def test_subtask_results_rejected_factory(self):
        msg = factories.tasks.SubtaskResultsRejectedFactory()
        self.assertIsInstance(msg, message.tasks.SubtaskResultsRejected)

    def test_subtask_results_rejected(self):
        rct = factories.tasks.ReportComputedTaskFactory()
        reason = message.tasks.SubtaskResultsRejected.REASON\
            .VerificationNegative
        msg = factories.tasks.SubtaskResultsRejectedFactory(
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
    FACTORY = factories.tasks.TaskToComputeFactory
    MSG_CLASS = message.tasks.TaskToCompute

    def setUp(self):
        self.msg = self.FACTORY()

    def test_task_to_compute_basic(self):
        ttc = factories.tasks.TaskToComputeFactory()
        serialized = shortcuts.dump(ttc, None, None)
        msg = shortcuts.load(serialized, None, None)
        self.assertIsInstance(msg, message.tasks.TaskToCompute)

    def test_concent_enabled_attribute(self):
        ttc = factories.tasks.TaskToComputeFactory(concent_enabled=True)
        self.assertTrue(ttc.concent_enabled)

    def test_concent_enabled_default_true(self):
        ttc = message.tasks.TaskToCompute()
        self.assertTrue(ttc.concent_enabled)

    def test_concent_enabled_false(self):
        ttc = message.tasks.TaskToCompute(concent_enabled=False)
        self.assertFalse(ttc.concent_enabled)

    def test_ethereum_address(self):
        msg = factories.tasks.TaskToComputeFactory()
        serialized = shortcuts.dump(msg, None, None)
        msg_l = shortcuts.load(serialized, None, None)
        for addr_slot in (
                'requestor_ethereum_address',
                'provider_ethereum_address'):
            address = getattr(msg_l, addr_slot)
            self.assertEqual(len(address), 2 + (20*2))

    def test_task_id(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.compute_task_def['task_id'])  # noqa pylint:disable=unsubscriptable-object

    def test_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.compute_task_def['subtask_id'])  # noqa pylint:disable=unsubscriptable-object

    def test_past_deadline(self):
        now = calendar.timegm(time.gmtime())
        ttc = factories.tasks.TaskToComputeFactory.past_deadline()
        self.assertGreater(now, ttc.compute_task_def.get('deadline'))


class ReportComputedTaskTest(mixins.RegisteredMessageTestMixin,
                             mixins.SerializationMixin,
                             unittest.TestCase):
    FACTORY = factories.tasks.ReportComputedTaskFactory
    MSG_CLASS = message.tasks.ReportComputedTask

    def setUp(self):
        self.msg = self.FACTORY()

    def test_task_id(self):
        self.assertEqual(self.msg.task_id, self.msg.task_to_compute.task_id)

    def test_factory_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.task_to_compute.subtask_id)


class AckReportComputedTaskTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = message.tasks.AckReportComputedTask
    FACTORY = factories.tasks.AckReportComputedTaskFactory
    TASK_ID_PROVIDER = 'report_computed_task'


class RejectReportComputedTaskTestCase(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = message.tasks.RejectReportComputedTask
    FACTORY = factories.tasks.RejectReportComputedTaskFactory.\
        with_task_to_compute
    TASK_ID_PROVIDER = 'attached_task_to_compute'


class RejectRctCctTestCase(mixins.TaskIdMixin, unittest.TestCase):
    MSG_CLASS = message.tasks.RejectReportComputedTask
    FACTORY = factories.tasks.RejectReportComputedTaskFactory.\
        with_cannot_compute_task
    TASK_ID_PROVIDER = 'cannot_compute_task'


class RejectRctTfTestCase(mixins.TaskIdMixin, unittest.TestCase):
    MSG_CLASS = message.tasks.RejectReportComputedTask
    FACTORY = factories.tasks.RejectReportComputedTaskFactory.\
        with_task_failure
    TASK_ID_PROVIDER = 'task_failure'


class TaskMessageVerificationTest(unittest.TestCase):
    @staticmethod
    def _fake_keys():
        return cryptography.ECCx(None)

    def setUp(self):
        self.provider_keys = self._fake_keys()
        self.requestor_keys = self._fake_keys()
        self.other_keys = self._fake_keys()

    def get_ttc(self, **kwargs):
        return factories.tasks.TaskToComputeFactory(
            provider_public_key=self.provider_keys.raw_pubkey,
            requestor_public_key=self.requestor_keys.raw_pubkey,
            **kwargs,
        )

    def get_rtc(self, **kwargs):
        return factories.tasks.ReportComputedTaskFactory(
            **kwargs,
        )

    def get_signed_rtc(self):
        return self.get_rtc(
            task_to_compute=self.get_ttc(
                sign__privkey=self.requestor_keys.raw_privkey
            ),
            sign__privkey=self.provider_keys.raw_privkey
        )

    def test_validate_ownership(self):
        ttc = self.get_ttc(
            sign__privkey=self.requestor_keys.raw_privkey,
        )
        self.assertTrue(ttc.validate_ownership())

    def test_validate_ownership_no_sig(self):
        ttc = self.get_ttc()
        with self.assertRaises(exceptions.InvalidSignature):
            ttc.validate_ownership()

    def test_validate_ownership_mismatch(self):
        ttc = self.get_ttc(
            sign__privkey=self.provider_keys.raw_privkey,
        )
        with self.assertRaises(exceptions.InvalidSignature):
            ttc.validate_ownership()

    def test_chain(self):
        rtc = self.get_signed_rtc()
        self.assertTrue(rtc.validate_ownership_chain())

    def test_chain_parent_no_sig(self):
        rtc = self.get_rtc(
            task_to_compute=self.get_ttc(
                sign__privkey=self.requestor_keys.raw_privkey
            ),
        )
        with self.assertRaises(exceptions.InvalidSignature):
            rtc.validate_ownership_chain()

    def test_chain_child_no_sig(self):
        rtc = self.get_rtc(
            task_to_compute=self.get_ttc(),
            sign__privkey=self.provider_keys.raw_privkey
        )
        with self.assertRaises(exceptions.InvalidSignature):
            rtc.validate_ownership_chain()

    def test_chain_parent_mismatch(self):
        rtc = self.get_rtc(
            task_to_compute=self.get_ttc(
                sign__privkey=self.requestor_keys.raw_privkey
            ),
            sign__privkey=self.requestor_keys.raw_privkey
        )
        with self.assertRaises(exceptions.InvalidSignature):
            rtc.validate_ownership_chain()

    def test_chain_child_mismatch(self):
        rtc = self.get_rtc(
            task_to_compute=self.get_ttc(
                sign__privkey=self.provider_keys.raw_privkey
            ),
            sign__privkey=self.provider_keys.raw_privkey
        )
        with self.assertRaises(exceptions.InvalidSignature):
            rtc.validate_ownership_chain()

    def test_verify_owners(self):
        rtc = self.get_signed_rtc()
        self.assertTrue(
            rtc.verify_owners(
                provider_public_key=self.provider_keys.raw_pubkey,
                requestor_public_key=self.requestor_keys.raw_pubkey,
            )
        )

    def test_verify_owners_provider_only(self):
        rtc = self.get_signed_rtc()
        self.assertTrue(
            rtc.verify_owners(
                provider_public_key=self.provider_keys.raw_pubkey))

    def test_verify_owners_requestor_only(self):
        rtc = self.get_signed_rtc()
        self.assertTrue(
            rtc.verify_owners(
                requestor_public_key=self.requestor_keys.raw_pubkey))

    def test_verify_owners_provider_mismatch(self):
        rtc = self.get_signed_rtc()
        with self.assertRaises(exceptions.OwnershipMismatch) as e:
            rtc.verify_owners(
                provider_public_key=self.other_keys.raw_pubkey,
                requestor_public_key=self.requestor_keys.raw_pubkey,
            )

        self.assertIn('provider', str(e.exception))

    def test_verify_owners_requestor_mismatch(self):
        rtc = self.get_signed_rtc()
        with self.assertRaises(exceptions.OwnershipMismatch) as e:
            rtc.verify_owners(
                provider_public_key=self.provider_keys.raw_pubkey,
                requestor_public_key=self.other_keys.raw_pubkey,
            )
        self.assertIn('requestor', str(e.exception))

