# pylint: disable=no-self-use
import calendar
import time
import unittest
import unittest.mock as mock

from ethereum.utils import sha3

from golem_messages import cryptography
from golem_messages import exceptions
from golem_messages import factories
from golem_messages import message
from golem_messages import shortcuts
from golem_messages.utils import encode_hex, decode_hex

from tests.message import mixins


class WantToComputeTaskTest(unittest.TestCase):
    def test_concent_enabled_default_false(self):
        wtct = message.tasks.WantToComputeTask()
        self.assertFalse(wtct.concent_enabled)

    def test_concent_enabled_none_false(self):
        wtct = message.tasks.WantToComputeTask(concent_enabled=None)
        self.assertFalse(wtct.concent_enabled)
        self.assertIsInstance(wtct.concent_enabled, bool)

    def test_concent_enabled_true(self):
        wtct = message.tasks.WantToComputeTask(concent_enabled=True)
        self.assertTrue(wtct.concent_enabled)


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

    def test_type(self):
        ctd = message.ComputeTaskDef()
        ctd['src_code'] = "custom code"
        msg = factories.tasks.TaskToComputeFactory(compute_task_def=ctd)
        s = msg.serialize()
        msg2 = message.Message.deserialize(s, None)
        self.assertEqual(ctd, msg2.compute_task_def)
        self.assertIsInstance(msg2.compute_task_def, message.ComputeTaskDef)


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

    def test_concent_enabled_default_false(self):
        ttc = message.tasks.TaskToCompute()
        self.assertFalse(ttc.concent_enabled)

    def test_concent_enabled_false(self):
        ttc = message.tasks.TaskToCompute(concent_enabled=False)
        self.assertFalse(ttc.concent_enabled)

    def test_concent_enabled_none_false(self):
        ttc = message.tasks.TaskToCompute(concent_enabled=None)
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

    def test_ethereum_address_provider(self):
        msg = factories.tasks.TaskToComputeFactory()
        provider_public_key = decode_hex(msg.provider_ethereum_public_key)

        self.assertEqual(msg.provider_ethereum_address,
                         '0x' + sha3(provider_public_key)[12:].hex())

    def test_ethereum_address_requestor(self):
        msg = factories.tasks.TaskToComputeFactory()
        requestor_public_key = decode_hex(msg.requestor_ethereum_public_key)

        self.assertEqual(msg.requestor_ethereum_address,
                         '0x' + sha3(requestor_public_key)[12:].hex())

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

    @staticmethod
    def _dump_and_load(msg):
        msg_d = shortcuts.dump(msg, None, None)
        return shortcuts.load(msg_d, None, None)

    def test_size(self):
        size = 1234567
        ttc = self._dump_and_load(
            factories.tasks.TaskToComputeFactory(size=size))
        self.assertEqual(ttc.size, size)

    def test_size_notint(self):
        ttc = factories.tasks.TaskToComputeFactory(size=None)
        with self.assertRaises(exceptions.FieldError):
            self._dump_and_load(ttc)


class PriceTaskToComputeTestCase(unittest.TestCase):
    def setUp(self):
        self.msg = factories.tasks.TaskToComputeFactory()

    def test_valid_price_value(self):
        price = 1994
        self.msg.price = price
        s = self.msg.serialize()
        msg2 = message.Message.deserialize(s, None)
        self.assertEqual(msg2.price, price)

    def test_invalid_price_value(self):
        price = '1994'
        self.msg.price = price
        s = self.msg.serialize()
        with self.assertRaises(exceptions.FieldError):
            message.Message.deserialize(s, None)


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

    def test_validate_owner_requestor(self):
        requestor_keys = cryptography.ECCx(None)
        arct = self.FACTORY(
            report_computed_task__task_to_compute__requestor_public_key=encode_hex(requestor_keys.raw_pubkey),  # noqa pylint:disable=line-too-long
            sign__privkey=requestor_keys.raw_privkey,
        )
        self.assertTrue(arct.validate_ownership())

    def test_validate_owner_concent(self):
        concent_keys = cryptography.ECCx(None)
        arct = self.FACTORY(
            sign__privkey=concent_keys.raw_privkey,
        )
        self.assertTrue(
            arct.validate_ownership(
                concent_public_key=concent_keys.raw_pubkey))

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


class RejectReportComputedTaskSlotValidationTest(unittest.TestCase):
    FACTORY = factories.tasks.RejectReportComputedTaskFactory

    @staticmethod
    def dump_and_load(msg):
        return message.base.Message.deserialize(msg.serialize(), lambda m: m)

    def test_validate_task_to_compute(self):
        msg = self.FACTORY.with_task_to_compute()
        msg2 = self.dump_and_load(msg)
        self.assertEqual(msg, msg2)

    def test_fail_task_to_compute(self):
        msg = self.FACTORY(attached_task_to_compute='blah')
        with self.assertRaises(exceptions.FieldError):
            self.dump_and_load(msg)

    def test_validate_cannot_compute_task(self):
        msg = self.FACTORY.with_cannot_compute_task()
        msg2 = self.dump_and_load(msg)
        self.assertEqual(msg, msg2)

    def test_fail_cannot_compute_task(self):
        msg = self.FACTORY(
            cannot_compute_task=factories.tasks.TaskToComputeFactory())
        with self.assertRaises(exceptions.FieldError):
            self.dump_and_load(msg)

    def test_validate_task_failure(self):
        msg = self.FACTORY.with_task_failure()
        msg2 = self.dump_and_load(msg)
        self.assertEqual(msg, msg2)

    def test_fail_task_failure(self):
        msg = self.FACTORY(
            task_failure=factories.tasks.TaskToComputeFactory())
        with self.assertRaises(exceptions.FieldError):
            self.dump_and_load(msg)


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
            provider_public_key=encode_hex(self.provider_keys.raw_pubkey),
            requestor_public_key=encode_hex(self.requestor_keys.raw_pubkey),
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


class CannotComputeTaskTest(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = message.tasks.CannotComputeTask
    FACTORY = factories.tasks.CannotComputeTaskFactory
    TASK_ID_PROVIDER = 'task_to_compute'

    def test_factory_default_reason(self):
        msg = self.FACTORY()
        self.assertIsNotNone(msg.reason)


class TaskFailureTest(
        mixins.RegisteredMessageTestMixin,
        mixins.TaskIdMixin,
        mixins.SerializationMixin,
        unittest.TestCase):
    MSG_CLASS = message.tasks.TaskFailure
    FACTORY = factories.tasks.TaskFailureFactory
    TASK_ID_PROVIDER = 'task_to_compute'
