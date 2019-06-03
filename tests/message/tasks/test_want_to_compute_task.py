import unittest

from eth_utils import is_checksum_address

from golem_messages import exceptions
from golem_messages import factories
from golem_messages import message
from golem_messages import shortcuts
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
        self.assertTrue(is_checksum_address(wtct.provider_ethereum_address))

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
