# pylint: disable=no-self-use
import calendar
import time
import unittest
import unittest.mock as mock
import uuid

from eth_utils import is_checksum_address, to_checksum_address
from ethereum.utils import sha3
import factory

from golem_messages import cryptography
from golem_messages import dump
from golem_messages import exceptions
from golem_messages import factories
from golem_messages import load
from golem_messages import message
from golem_messages import shortcuts
from golem_messages.datastructures import promissory
from golem_messages.datastructures.tasks import TaskHeader
from golem_messages.factories.datastructures.tasks import TaskHeaderFactory
from golem_messages.factories.helpers import override_timestamp
from golem_messages.utils import encode_hex, decode_hex
from tests.message import mixins, helpers


class WantToComputeTaskTest(unittest.TestCase, mixins.SerializationMixin):
    FACTORY = factories.tasks.WantToComputeTaskFactory

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

    def test_extra_data(self):
        extra_data_content = {'some': 'content'}
        wtct = message.tasks.WantToComputeTask(extra_data=extra_data_content)
        wtct2 = helpers.dump_and_load(wtct)
        self.assertEqual(wtct2.extra_data, extra_data_content)

    def test_provider_ethereum_address_checksum(self):
        wtct = self.FACTORY()
        self.assertTrue(wtct.provider_ethereum_public_key)
        self.assertTrue(is_checksum_address(wtct.provider_ethereum_address))

    def test_ethereum_address_provider(self):
        wtct = self.FACTORY()
        provider_public_key = decode_hex(wtct.provider_ethereum_public_key)

        self.assertEqual(wtct.provider_ethereum_address,
                         to_checksum_address(
                             '0x' + sha3(provider_public_key)[12:].hex()))

    def test_ethereum_address(self):
        wtct = self.FACTORY()
        serialized = shortcuts.dump(wtct, None, None)
        msg_l = shortcuts.load(serialized, None, None)
        self.assertEqual(len(msg_l.provider_ethereum_address), 2 + (20*2))

    def test_task_id(self):
        wtct = self.FACTORY()
        self.assertEqual(wtct.task_id, wtct.task_header.task_id)

    def test_num_subtasks_default_1(self):
        wtct = message.tasks.WantToComputeTask()
        self.assertIsInstance(wtct.num_subtasks, int)
        self.assertEqual(wtct.num_subtasks, 1)

    def test_num_subtasks_none_1(self):
        wtct = message.tasks.WantToComputeTask(num_subtasks=None)
        self.assertEqual(wtct.num_subtasks, 1)
        self.assertIsInstance(wtct.num_subtasks, int)

    def test_num_subtasks_more_than_1(self):
        wtct = message.tasks.WantToComputeTask(num_subtasks=17)
        wtct_1 = helpers.dump_and_load(wtct)
        self.assertEqual(wtct.num_subtasks, 17)
        self.assertEqual(wtct.num_subtasks, wtct_1.num_subtasks)

    def test_num_subtasks_non_int_raises(self):
        wtct = message.tasks.WantToComputeTask(num_subtasks=3.14)
        serialized = shortcuts.dump(wtct, None, None)
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"Should be an integer \[num_subtasks:3.14\]"
        ):
            shortcuts.load(serialized, None, None)

    def test_num_subtasks_zero_raises(self):
        wtct = message.tasks.WantToComputeTask(num_subtasks=0)
        serialized = shortcuts.dump(wtct, None, None)
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"Should be a positive integer \[num_subtasks:0\]"
        ):
            shortcuts.load(serialized, None, None)

    def test_num_subtasks_negative_raises(self):
        wtct = message.tasks.WantToComputeTask(num_subtasks=-7)
        serialized = shortcuts.dump(wtct, None, None)
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"Should be a positive integer \[num_subtasks:-7\]"
        ):
            shortcuts.load(serialized, None, None)

    def test_concent_enabled_invokes_another_constructor(self):
        from golem_messages.datastructures import MessageHeader
        wtct = self.FACTORY()
        self.assertIsNotNone(wtct.header)
        self.assertIsInstance(wtct.header, MessageHeader)


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

    def test_extra_data(self):
        ctd = factories.tasks.ComputeTaskDefFactory()
        extra_data = ctd['extra_data']
        self.assertIsInstance(extra_data, dict)
        self.assertEqual(extra_data['path_root'], '')
        self.assertTrue(extra_data['start_task'])
        self.assertTrue(extra_data['end_task'])
        self.assertTrue(extra_data['total_tasks'])
        self.assertTrue(extra_data['outfilebasename'])
        self.assertTrue(extra_data['scene_file'])
        self.assertTrue(extra_data['script_src'])
        self.assertTrue(extra_data['frames'])
        self.assertTrue(extra_data['output_format'])


class SubtaskResultsAcceptedTest(mixins.RegisteredMessageTestMixin,
                                 mixins.SerializationMixin,
                                 mixins.TaskIdMixin,
                                 unittest.TestCase):
    FACTORY = factories.tasks.SubtaskResultsAcceptedFactory
    MSG_CLASS = message.tasks.SubtaskResultsAccepted
    TASK_ID_PROVIDER = 'report_computed_task'

    def test_factory(self):
        self.assertIsInstance(self.msg, message.tasks.SubtaskResultsAccepted)

    def test_report_computed_task_wrong_class(self):
        with self.assertRaises(exceptions.FieldError):
            message.tasks.SubtaskResultsAccepted(slots=(
                ('report_computed_task', 'something else'),
            ))

    def test_report_computed_task_correct(self):
        msg = message.tasks.SubtaskResultsAccepted(slots=(
            (
                'report_computed_task',
                helpers.single_nested(
                    factories.tasks.ReportComputedTaskFactory(),
                ),
            ),
        ))
        self.assertIsInstance(
            msg.report_computed_task,
            message.tasks.ReportComputedTask,
        )

    def test_payment_ts_in_future_validation_raises(self):
        serialized_sra = self._get_serialized_sra(payment_ts_offset=1)
        with self.assertRaises(exceptions.ValidationError):
            load(serialized_sra, None, None)

    def test_payment_ts_in_past_validation_raises(self):
        serialized_sra = self._get_serialized_sra(payment_ts_offset=-901)
        with self.assertRaises(exceptions.ValidationError):
            load(serialized_sra, None, None)

    def test_payment_ts_validation_ok(self):
        serialized_sra = self._get_serialized_sra()
        try:
            load(serialized_sra, None, None)
        except Exception:   # pylint: disable=broad-except
            self.fail("Should pass validation, but didn't")

    def _get_serialized_sra(self, payment_ts_offset=0):
        timestamp = calendar.timegm(time.gmtime())
        payment_ts = timestamp + payment_ts_offset
        sra = self.FACTORY(payment_ts=payment_ts)
        override_timestamp(sra, timestamp)
        return dump(sra, None, None)


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


class TaskToComputeTest(mixins.RegisteredMessageTestMixin,
                        mixins.SerializationMixin,
                        unittest.TestCase, ):
    FACTORY = factories.tasks.TaskToComputeFactory
    MSG_CLASS = message.tasks.TaskToCompute

    def setUp(self):
        self.msg: message.tasks.TaskToCompute = self.FACTORY()

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

    def test_ethereum_address_requestor(self):
        msg = factories.tasks.TaskToComputeFactory()
        requestor_public_key = decode_hex(msg.requestor_ethereum_public_key)
        serialized = shortcuts.dump(msg, None, None)
        msg_l = shortcuts.load(serialized, None, None)
        self.assertEqual(len(msg_l.requestor_ethereum_address), 2 + (20*2))
        self.assertEqual(msg.requestor_ethereum_address,
                         to_checksum_address(
                             '0x' + sha3(requestor_public_key)[12:].hex()))

    def test_ethereum_address_provider(self):
        msg = factories.tasks.TaskToComputeFactory()
        provider_public_key = decode_hex(msg.provider_ethereum_public_key)
        serialized = shortcuts.dump(msg, None, None)
        msg_l = shortcuts.load(serialized, None, None)
        self.assertEqual(len(msg_l.provider_ethereum_address), 2 + (20*2))
        self.assertEqual(msg_l.provider_ethereum_address,
                         msg_l.want_to_compute_task.provider_ethereum_address)
        self.assertEqual(msg.provider_ethereum_address,
                         to_checksum_address(
                             '0x' + sha3(provider_public_key)[12:].hex()))

    def test_public_key_provider(self):
        msg = factories.tasks.TaskToComputeFactory()
        self.assertEqual(msg.provider_ethereum_public_key,
                         msg.want_to_compute_task.provider_ethereum_public_key)

    def test_task_id(self):
        self.assertEqual(self.msg.task_id,
                         self.msg.compute_task_def['task_id'])  # noqa pylint:disable=unsubscriptable-object

    def test_subtask_id(self):
        self.assertEqual(self.msg.subtask_id,
                         self.msg.compute_task_def['subtask_id'])  # noqa pylint:disable=unsubscriptable-object

    def _test_spoofed_id(self, key):
        self.msg.compute_task_def[key] = str(uuid.uuid4())  # noqa pylint:disable=unsupported-assignment-operation

        requestor_keys = cryptography.ECCx(None)
        self.msg.requestor_ethereum_public_key = encode_hex(
            requestor_keys.raw_pubkey,
        )
        self.msg.generate_ethsig(private_key=requestor_keys.raw_privkey)
        s = self.msg.serialize()
        with self.assertRaises(exceptions.FieldError):
            message.Message.deserialize(s, None)

    def test_spoofed_task_id(self):
        self._test_spoofed_id('task_id')

    def test_spoofed_subtask_id(self):
        self._test_spoofed_id('subtask_id')

    def test_golem_id_shortcut(self):
        task_id = 'tid'
        subtask_id = 'sid'
        ttc = factories.tasks.TaskToComputeFactory(
            task_id=task_id,
            subtask_id=subtask_id,
        )
        self.assertEqual(ttc.task_id, task_id)
        self.assertEqual(ttc.compute_task_def['task_id'], task_id)  # noqa pylint: disable=unsubscriptable-object
        self.assertEqual(ttc.subtask_id, subtask_id)
        self.assertEqual(ttc.compute_task_def['subtask_id'], subtask_id)  # noqa pylint: disable=unsubscriptable-object

    def test_no_compute_task_def(self):
        # Should not raise
        ttc = factories.tasks.TaskToComputeFactory(compute_task_def=None)
        self.assertEqual(ttc.task_id, None)
        self.assertEqual(ttc.subtask_id, None)

    def test_validate_ownership_chain(self):
        # Should not raise
        requestor_keys = cryptography.ECCx(None)
        task_header: TaskHeader = TaskHeaderFactory()
        task_header.sign(requestor_keys.raw_privkey)  # noqa pylint: disable=no-value-for-parameter

        wtc = factories.tasks.WantToComputeTaskFactory(
            task_header=task_header
        )

        ttc: message.tasks.TaskToCompute = factories.tasks.TaskToComputeFactory(
            requestor_public_key=encode_hex(
                requestor_keys.raw_pubkey,
            ),
            want_to_compute_task=wtc,
        )
        ttc.sign_message(requestor_keys.raw_privkey)  # noqa pylint: disable=no-value-for-parameter

        ttc.validate_ownership_chain()

    def test_validate_ownership_chain_raises_when_invalid(self):
        requestor_keys = cryptography.ECCx(None)
        different_keys = cryptography.ECCx(None)
        task_header: TaskHeader = TaskHeaderFactory()
        task_header.sign(different_keys.raw_privkey)  # noqa pylint: disable=no-value-for-parameter

        wtc = factories.tasks.WantToComputeTaskFactory(
            task_header=task_header
        )

        ttc: message.tasks.TaskToCompute = factories.tasks.TaskToComputeFactory(
            requestor_public_key=encode_hex(
                requestor_keys.raw_pubkey,
            ),
            want_to_compute_task=wtc,
        )
        ttc.sign_message(requestor_keys.raw_privkey)  # noqa pylint: disable=no-value-for-parameter
        with self.assertRaises(exceptions.InvalidSignature):
            ttc.validate_ownership_chain()

    def test_past_deadline(self):
        now = calendar.timegm(time.gmtime())
        ttc = factories.tasks.TaskToComputeFactory.past_deadline()
        self.assertGreater(now, ttc.compute_task_def.get('deadline'))

    def test_size(self):
        size = 1234567
        ttc = helpers.dump_and_load(
            factories.tasks.TaskToComputeFactory(size=size))
        self.assertEqual(ttc.size, size)

    def test_size_notint(self):
        ttc = factories.tasks.TaskToComputeFactory(size=None)
        with self.assertRaises(exceptions.FieldError):
            helpers.dump_and_load(ttc)


class TaskToComputePromissoryNotesTest(
        mixins.PromissoryNoteMixin,
        unittest.TestCase,
):
    FACTORY = factories.tasks.TaskToComputeFactory

    def setUp(self):
        self.msg: message.tasks.TaskToCompute = self.FACTORY()
        # arbitrary address
        self.gntdeposit = '0x89915ddA14eFd6b064da953431E8b7f902d89c83'

    def test_promissory_note(self):
        requestor_keys = cryptography.ECCx(None)

        ttc: message.tasks.TaskToCompute = self.FACTORY(
            ethsig__keys=requestor_keys
        )
        ttc.sign_promissory_note(private_key=requestor_keys.raw_privkey)

        self.assertIsInstance(
            ttc.promissory_note_sig,
            promissory.PromissoryNoteSig,
        )

        ttc2: message.tasks.TaskToCompute = helpers.dump_and_load(ttc)

        self.assertEqual(
            ttc.promissory_note_sig,
            tuple(ttc2.promissory_note_sig)
        )

        self.assertTrue(
            ttc2.verify_promissory_note(),
        )

    def test_promissory_note_empty(self):
        self.assertFalse(
            self.msg.verify_promissory_note()
        )

    def test_promissory_note_bad(self):
        requestor_keys = cryptography.ECCx(None)
        self.msg.sign_promissory_note(private_key=requestor_keys.raw_privkey)
        self.assertFalse(self.msg.verify_promissory_note())

    def test_concent_promissory_note(self):
        requestor_keys = cryptography.ECCx(None)

        ttc: message.tasks.TaskToCompute = self.FACTORY(
            requestor_ethereum_public_key=encode_hex(
                requestor_keys.raw_pubkey
            ),
            ethsig__privkey=requestor_keys.raw_privkey,
        )
        ttc.sign_concent_promissory_note(
            self.gntdeposit,
            private_key=requestor_keys.raw_privkey
        )

        self.assertIsInstance(
            ttc.concent_promissory_note_sig,
            promissory.PromissoryNoteSig,
        )

        ttc2: message.tasks.TaskToCompute = helpers.dump_and_load(ttc)

        self.assertEqual(
            ttc.concent_promissory_note_sig,
            tuple(ttc2.concent_promissory_note_sig)
        )

        self.assertTrue(
            ttc2.verify_concent_promissory_note(self.gntdeposit),
        )


class TaskToComputeSignedChainFactory(unittest.TestCase):
    def test_factory_with_signed_nested_messages(self):
        requestor_keys = cryptography.ECCx(None)
        provider_keys = cryptography.ECCx(None)

        ttc: message.tasks.TaskToCompute = \
            factories.tasks.TaskToComputeFactory.with_signed_nested_messages(
                requestor_keys=requestor_keys,
                provider_keys=provider_keys,
            )
        wtct: message.tasks.WantToComputeTask = ttc.want_to_compute_task
        th: TaskHeader = wtct.task_header

        self.assertTrue(ttc.verify_signature(requestor_keys.raw_pubkey))
        self.assertTrue(wtct.verify_signature(provider_keys.raw_pubkey))
        self.assertTrue(th.verify(requestor_keys.raw_pubkey))
        self.assertEqual(ttc.requestor_id, th.task_owner.key)
        self.assertEqual(ttc.task_id, th.task_id)


class TaskToComputeEthereumAddressChecksum(unittest.TestCase):
    def test_requestor_ethereum_address_checksum(self):
        ttc = factories.tasks.TaskToComputeFactory()
        self.assertTrue(ttc.requestor_ethereum_public_key)
        self.assertTrue(is_checksum_address(ttc.requestor_ethereum_address))


# pylint:disable=protected-access


class TaskToComputeEthsigTest(unittest.TestCase):

    def test_ethsig(self):
        msg: message.tasks.TaskToCompute = \
            factories.tasks.TaskToComputeFactory()
        self.assertTrue(msg.ethsig)
        msg2 = helpers.dump_and_load(msg)
        self.assertEqual(msg2.ethsig, msg.ethsig)

    def test_ethsig_none(self):
        msg: message.tasks.TaskToCompute = \
            factories.tasks.TaskToComputeFactory(
                requestor_ethereum_public_key=encode_hex(
                    cryptography.ECCx(None).raw_pubkey))
        self.assertIsNone(msg.ethsig)
        with self.assertRaises(exceptions.InvalidSignature):
            helpers.dump_and_load(msg)

    @staticmethod
    def _get_ethkeys_and_ttc():
        requestor_eth_keys = cryptography.ECCx(None)
        msg: message.tasks.TaskToCompute = \
            factories.tasks.TaskToComputeFactory(
                requestor_ethereum_public_key=encode_hex(
                    requestor_eth_keys.raw_pubkey
                )
            )
        return requestor_eth_keys, msg

    def test_generate_ethsig(self):
        requestor_eth_keys, msg = self._get_ethkeys_and_ttc()
        msg.generate_ethsig(requestor_eth_keys.raw_privkey)
        self.assertTrue(msg.verify_ethsig())

    def test_generate_ethsig_public_key_none(self):
        keys = cryptography.ECCx(None)
        ttc = factories.tasks.TaskToComputeFactory(
            requestor_ethereum_public_key=None,
            ethsig__disable=True,
        )
        with self.assertRaisesRegex(exceptions.FieldError,
                                    "^It doesn't really make sense"):
            ttc.generate_ethsig(keys.raw_privkey)

    def test_verify_ethsig(self):
        provider_keys = cryptography.ECCx(None)
        requestor_keys = cryptography.ECCx(None)
        requestor_eth_keys, msg = self._get_ethkeys_and_ttc()
        msg.generate_ethsig(requestor_eth_keys.raw_privkey)
        self.assertTrue(msg.ethsig)
        data = shortcuts.dump(
            msg, requestor_keys.raw_privkey, provider_keys.raw_pubkey)
        msg2: message.tasks.TaskToCompute = shortcuts.load(
            data, provider_keys.raw_privkey, requestor_keys.raw_pubkey)
        self.assertTrue(msg2.ethsig)
        self.assertTrue(msg2.verify_ethsig())


# pylint:enable=protected-access


class TaskToComputeEthsigFactory(unittest.TestCase):

    @staticmethod
    def _get_ethkeys():
        return cryptography.ECCx(None)

    def test_factory_ethsig_correct_default(self):
        ttc = factories.tasks.TaskToComputeFactory()
        self.assertTrue(ttc.verify_ethsig())

    def test_factory_keys(self):
        requestor_eth_keys = self._get_ethkeys()
        ttc = factories.tasks.TaskToComputeFactory(
            ethsig__keys=requestor_eth_keys)
        self.assertTrue(ttc.verify_ethsig())
        self.assertEqual(
            ttc.requestor_ethereum_public_key,
            encode_hex(requestor_eth_keys.raw_pubkey)
        )

    def test_factory_fail_keys_and_privkey(self):
        requestor_eth_keys = self._get_ethkeys()
        with self.assertRaisesRegex(factory.errors.InvalidDeclarationError,
                                    "^You need to specify either"):
            factories.tasks.TaskToComputeFactory(
                ethsig__keys=requestor_eth_keys,
                ethsig__privkey=requestor_eth_keys.raw_privkey
            )

    def test_factory_requestor_ethereum_public_key_and_privkey(self):
        requestor_eth_keys = self._get_ethkeys()
        ttc = factories.tasks.TaskToComputeFactory(
            requestor_ethereum_public_key=encode_hex(
                requestor_eth_keys.raw_pubkey
            ),
            ethsig__privkey=requestor_eth_keys.raw_privkey
        )
        self.assertTrue(ttc.verify_ethsig())

    def test_factory_requestor_ethereum_public_key_nosig(self):
        requestor_eth_keys = self._get_ethkeys()
        ttc = factories.tasks.TaskToComputeFactory(
            requestor_ethereum_public_key=encode_hex(
                requestor_eth_keys.raw_pubkey
            )
        )
        self.assertIsNone(ttc.ethsig)  # noqa pylint:disable=protected-access
        with self.assertRaises(exceptions.InvalidSignature):
            ttc.verify_ethsig()

    def test_fail_factory_privkey_only(self):
        requestor_eth_keys = self._get_ethkeys()
        with self.assertRaisesRegex(exceptions.FieldError,
                                    "^It doesn't really make sense"):
            factories.tasks.TaskToComputeFactory(
                ethsig__privkey=requestor_eth_keys.raw_privkey
            )

    def test_fail_factory_privkey_and_disable(self):
        requestor_eth_keys = self._get_ethkeys()
        with self.assertRaisesRegex(factory.errors.InvalidDeclarationError,
                                    ".*disable the default ethereum signature "
                                    "generation and at the same time "
                                    "provide the private key"):
            factories.tasks.TaskToComputeFactory(
                ethsig__privkey=requestor_eth_keys.raw_privkey,
                ethsig__disable=True,
            )

    def test_fail_factory_keys_and_disable(self):
        with self.assertRaisesRegex(factory.errors.InvalidDeclarationError,
                                    ".*disable the default ethereum signature "
                                    "generation and at the same time "
                                    "provide the private key"):
            factories.tasks.TaskToComputeFactory(
                ethsig__keys=self._get_ethkeys(),
                ethsig__disable=True,
            )


class PriceTaskToComputeTestCase(unittest.TestCase):
    def setUp(self):
        self.factory = factories.tasks.TaskToComputeFactory

    def test_valid_price_value(self):
        price = 1994
        msg = self.factory(price=price)
        s = msg.serialize()
        msg2 = message.Message.deserialize(s, None)
        self.assertEqual(msg2.price, price)

    def test_invalid_price_value(self):
        price = '1994'
        msg = self.factory(price=price)
        s = msg.serialize()
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
        task_header: TaskHeader = TaskHeaderFactory()
        task_header.sign(self.requestor_keys.raw_privkey)  # noqa pylint: disable=no-value-for-parameter
        return factories.tasks.TaskToComputeFactory(
            requestor_public_key=encode_hex(self.requestor_keys.raw_pubkey),
            want_to_compute_task=factories.tasks.WantToComputeTaskFactory(
                provider_public_key=encode_hex(self.provider_keys.raw_pubkey),
                task_header=task_header,
            ),
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
        with self.assertRaisesRegex(exceptions.OwnershipMismatch, 'provider'):
            rtc.verify_owners(
                provider_public_key=self.other_keys.raw_pubkey,
                requestor_public_key=self.requestor_keys.raw_pubkey,
            )

    def test_verify_owners_requestor_mismatch(self):
        rtc = self.get_signed_rtc()
        with self.assertRaisesRegex(exceptions.OwnershipMismatch, 'requestor'):
            rtc.verify_owners(
                provider_public_key=self.provider_keys.raw_pubkey,
                requestor_public_key=self.other_keys.raw_pubkey,
            )


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


class WaitingForResultsTest(
        mixins.RegisteredMessageTestMixin,
        mixins.SerializationMixin,
        mixins.TaskIdMixin,
        unittest.TestCase):
    FACTORY = factories.tasks.WaitingForResultsFactory
    MSG_CLASS = message.tasks.WaitingForResults
    TASK_ID_PROVIDER = 'task_to_compute'
