# pylint:disable=no-self-use
import calendar
import time
import unittest
import uuid

from eth_utils import is_checksum_address, to_checksum_address
from ethereum.utils import sha3
import factory

from golem_messages import cryptography
from golem_messages import exceptions
from golem_messages import factories
from golem_messages import message
from golem_messages import shortcuts
from golem_messages.datastructures import promissory
from golem_messages.datastructures.tasks import TaskHeader
from golem_messages.factories.datastructures.tasks import TaskHeaderFactory
from golem_messages.factories.helpers import random_eth_pub_key
from golem_messages.utils import encode_hex, decode_hex
from tests.message import mixins, helpers


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
        serialized = shortcuts.dump(msg, None, None)
        msg_l = shortcuts.load(serialized, None, None)
        self.assertEqual(len(msg_l.provider_ethereum_address), 2 + (20*2))
        self.assertEqual(msg_l.provider_ethereum_address,
                         msg_l.want_to_compute_task.provider_ethereum_address)

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
        ttc.sign_promissory_note(
            self.gntdeposit,
            private_key=requestor_keys.raw_privkey
        )

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
            ttc2.verify_promissory_note(self.gntdeposit),
        )

    def test_promissory_note_empty(self):
        self.assertFalse(
            self.msg.verify_promissory_note(self.gntdeposit)
        )

    def test_promissory_note_bad(self):
        requestor_keys = cryptography.ECCx(None)
        self.msg.sign_promissory_note(
            self.gntdeposit,
            private_key=requestor_keys.raw_privkey
        )
        self.assertFalse(self.msg.verify_promissory_note(self.gntdeposit))

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

    def test_sign_all_promissory_notes(self):
        requestor_keys = cryptography.ECCx(None)
        ttc: message.tasks.TaskToCompute = self.FACTORY(
            ethsig__keys=requestor_keys
        )
        ttc.sign_all_promissory_notes(
            self.gntdeposit,
            private_key=requestor_keys.raw_privkey
        )
        ttc2: message.tasks.TaskToCompute = helpers.dump_and_load(ttc)
        self.assertTrue(
            ttc2.verify_all_promissory_notes(self.gntdeposit)
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
                requestor_ethereum_public_key=random_eth_pub_key())
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
